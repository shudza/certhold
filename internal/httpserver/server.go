// Package httpserver exposes the enrollment HTTP endpoint used during peer onboarding.
package httpserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/peerfiles"
)

// POSIX-style usernames: lowercase letter or underscore, then [a-z0-9_-], optional trailing $.
var validUsername = regexp.MustCompile(`^[a-z_][a-z0-9_-]*\$?$`)

// peerPassphraseBlock optionally encrypts the freshly installed peer key with a
// passphrase the operator types at /dev/tty (or presets via env). It reads $KEY,
// which each script body sets before splicing this in. Contains no '%' so it is
// safe inside the fmt.Sprintf-built script bodies.
const peerPassphraseBlock = `if [ "${CERTHOLD_NO_PASSPHRASE:-}" != "1" ]; then
  PASS="${CERTHOLD_KEY_PASSPHRASE:-}"
  if [ -z "$PASS" ] && [ -e /dev/tty ]; then
    printf 'Passphrase for this peer key (empty = none): ' > /dev/tty
    IFS= read -rs PASS < /dev/tty || PASS=""
    printf '\n' > /dev/tty
  fi
  if [ -n "$PASS" ]; then
    ssh-keygen -p -f "$KEY" -N "$PASS" -P "" >/dev/null 2>&1 || \
      ssh-keygen -p -f "$KEY" -N "$PASS" >/dev/null 2>&1 || true
    unset PASS
  fi
fi
`

// New builds the enroll HTTP handler. As of the sign-at-mint design the server no
// longer holds the CA: tarballs are built and signed by the enroll CLI and stored
// against the token row, so this handler is a CA-less byte-server.
func New(database *db.DB) http.Handler {
	mux := http.NewServeMux()
	tarball := enrollHandler(database)
	script := scriptHandler(database)
	mux.HandleFunc("GET /enroll/{token}", func(w http.ResponseWriter, r *http.Request) {
		tok := r.PathValue("token")
		if strings.HasSuffix(tok, ".sh") {
			script(w, r, strings.TrimSuffix(tok, ".sh"))
			return
		}
		tarball(w, r)
	})
	return mux
}

func scriptHandler(database *db.DB) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, token string) {
		if token == "" {
			writeErr(w, http.StatusBadRequest, "missing token")
			return
		}
		_, _, _, consumed, err := database.LookupToken(r.Context(), token)
		if err != nil {
			if errors.Is(err, db.ErrTokenNotFound) {
				writeErr(w, http.StatusNotFound, "token not found")
				return
			}
			writeErr(w, http.StatusInternalServerError, "lookup token failed")
			return
		}
		if consumed {
			writeErr(w, http.StatusGone, "token already consumed")
			return
		}

		instanceKey, _, _ := database.GetMeta(r.Context(), db.MetaInstanceKey)

		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
			scheme = p
		}
		baseURL := fmt.Sprintf("%s://%s", scheme, r.Host)
		body := v2Script(baseURL, token, instanceKey)
		w.Header().Set("Content-Type", "application/x-shellscript; charset=utf-8")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}
}

// v2Script builds the install script. It targets the invoking user's ~/.ssh
// ($HOME + id -un, so running as root targets /root/.ssh), untars the
// namespaced identity files into a staging dir, installs them, appends this
// instance's cert-authority line idempotently (grep-guarded by the CA pubkey),
// and splices the keyed client-config block with a per-instance,
// version-agnostic sed so multiple certhold instances coexist. It never reloads
// sshd and carries NO TrustedUserCAKeys/AuthorizedPrincipalsFile/RevokedKeys/
// HostCertificate directives.
func v2Script(baseURL, token, instanceKey string) string {
	block := peerfiles.V2SshClientBlock(instanceKey)
	keyFile := peerfiles.V2KeyFileName(instanceKey)

	var sb strings.Builder
	sb.WriteString("#!/usr/bin/env bash\nset -e\n")
	fmt.Fprintf(&sb, "TARGET_USER=\"$(id -un)\"\nUSER_HOME=\"$HOME\"\n")
	fmt.Fprintf(&sb, "[ -n \"$USER_HOME\" ] || { echo \"no \\$HOME\" >&2; exit 1; }\n")
	curl := fmt.Sprintf("curl -kfsSL %s/enroll/%s?user=$TARGET_USER", baseURL, token)
	writeV2Body(&sb, curl, keyFile, block, instanceKey)
	return sb.String()
}

func writeV2Body(sb *strings.Builder, curl, keyFile, block, instanceKey string) {
	fmt.Fprintf(sb, "mkdir -p \"$USER_HOME/.ssh\"\n")
	fmt.Fprintf(sb, "chmod 700 \"$USER_HOME/.ssh\"\n")
	fmt.Fprintf(sb, "STAGE=\"$(mktemp -d \"$USER_HOME/.ssh/.certhold.XXXXXX\")\"\n")
	fmt.Fprintf(sb, "%s | tar -xzC \"$STAGE\"\n", curl)
	fmt.Fprintf(sb, "echo \"\"\n")
	fmt.Fprintf(sb, "echo \"Changed files:\"\n")
	fmt.Fprintf(sb, "install -m 600 \"$STAGE/%s\" \"$USER_HOME/.ssh/%s\"\n", keyFile, keyFile)
	fmt.Fprintf(sb, "echo \"  + ~/.ssh/%s            (installed, 0600 - private key)\"\n", keyFile)
	fmt.Fprintf(sb, "install -m 644 \"$STAGE/%s-cert.pub\" \"$USER_HOME/.ssh/%s-cert.pub\"\n", keyFile, keyFile)
	fmt.Fprintf(sb, "echo \"  + ~/.ssh/%s-cert.pub   (installed, 0644 - certificate)\"\n", keyFile)
	fmt.Fprintf(sb, "KEY=\"$USER_HOME/.ssh/%s\"\n", keyFile)
	sb.WriteString(peerPassphraseBlock)

	fmt.Fprintf(sb, "touch \"$USER_HOME/.ssh/known_hosts\"\n")
	fmt.Fprintf(sb, "if [ -s \"$STAGE/known_hosts\" ]; then cat \"$STAGE/known_hosts\" >> \"$USER_HOME/.ssh/known_hosts\"; echo \"  ~ ~/.ssh/known_hosts                       (appended manager host key)\"; fi\n")
	fmt.Fprintf(sb, "touch \"$USER_HOME/.ssh/authorized_keys\"\n")
	fmt.Fprintf(sb, "chmod 600 \"$USER_HOME/.ssh/authorized_keys\"\n")
	// CA_KEY is the 3rd whitespace token of the shipped line
	// ("cert-authority,principals=..." <type> <base64> <comment>) — the raw CA
	// pubkey we grep for to dedupe. Workaround: TestEnrollV2User_Script pins the
	// canonical `if ! grep -qF "$CA_KEY" ... cat ... fi` guard line byte-for-byte,
	// so we can't fold an "appended" echo into it. Instead we capture the same
	// condition into APPENDED_AK with an extra identical grep first, then run the
	// pinned guard, then echo iff APPENDED_AK=1. Cost: one extra grep per install.
	// Removing it requires either changing the test pin or rewriting the guard.
	fmt.Fprintf(sb, "CA_KEY=\"$(awk '{print $3}' \"$STAGE/ca_authorized_keys\")\"\n")
	fmt.Fprintf(sb, "APPENDED_AK=0\n")
	fmt.Fprintf(sb, "if ! grep -qF \"$CA_KEY\" \"$USER_HOME/.ssh/authorized_keys\"; then APPENDED_AK=1; fi\n")
	fmt.Fprintf(sb, "if ! grep -qF \"$CA_KEY\" \"$USER_HOME/.ssh/authorized_keys\"; then cat \"$STAGE/ca_authorized_keys\" >> \"$USER_HOME/.ssh/authorized_keys\"; fi\n")
	fmt.Fprintf(sb, "if [ \"$APPENDED_AK\" = \"1\" ]; then echo \"  ~ ~/.ssh/authorized_keys                   (appended cert-authority line)\"; fi\n")

	fmt.Fprintf(sb, "touch \"$USER_HOME/.ssh/config\"\n")
	fmt.Fprintf(sb, "sed -i -E \"/^# BEGIN certhold %s( v[0-9]+)?\\$/,/^# END certhold %s( v[0-9]+)?\\$/d\" \"$USER_HOME/.ssh/config\"\n", instanceKey, instanceKey)
	fmt.Fprintf(sb, "cat >> \"$USER_HOME/.ssh/config\" <<'CHCFG_EOF'\n%sCHCFG_EOF\n", block)
	fmt.Fprintf(sb, "echo \"  ~ ~/.ssh/config                            (replaced certhold block)\"\n")

	fmt.Fprintf(sb, "rm -rf \"$STAGE\"\n")

	fmt.Fprintf(sb, "PEER_HOST=\"$(hostname -f 2>/dev/null || hostname || echo \"<your-host>\")\"\n")
	fmt.Fprintf(sb, "[ -n \"$PEER_HOST\" ] || PEER_HOST=\"<your-host>\"\n")
	fmt.Fprintf(sb, "echo \"\"\n")
	fmt.Fprintf(sb, "echo \"Success. Try:  ssh $TARGET_USER@$PEER_HOST\"\n")
	fmt.Fprintf(sb, "echo \"This address is what this peer reports for itself; if a different\"\n")
	fmt.Fprintf(sb, "echo \"address is reachable from the manager, pass --address to certhold enroll next time.\"\n")
}

func enrollHandler(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		token := r.PathValue("token")
		if token == "" {
			writeErr(w, http.StatusBadRequest, "missing token")
			return
		}

		queryUser := r.URL.Query().Get("user")

		// Pre-check the token row to enforce ?user= against any admin-preset
		// target_user BEFORE ConsumeToken burns it. Small TOCTOU window vs
		// concurrent consume is acceptable: token is the secret; admin can re-issue.
		// queryUser may be "root" (a --user root enrollment), which validUsername
		// accepts and which targets /root/.ssh.
		_, _, preTargetUser, preConsumed, err := database.LookupToken(ctx, token)
		if err != nil {
			if errors.Is(err, db.ErrTokenNotFound) {
				writeErr(w, http.StatusNotFound, "token not found")
				return
			}
			writeErr(w, http.StatusInternalServerError, "lookup token failed")
			return
		}
		if !preConsumed {
			if queryUser == "" {
				writeErr(w, http.StatusBadRequest, "user required")
				return
			}
			if len(queryUser) > 32 || !validUsername.MatchString(queryUser) {
				writeErr(w, http.StatusBadRequest, "invalid user")
				return
			}
			if preTargetUser != "" && preTargetUser != queryUser {
				writeErr(w, http.StatusBadRequest, "user mismatch")
				return
			}
		}

		peerName, _, _, tarball, err := database.ConsumeToken(ctx, token)
		if err != nil {
			switch {
			case errors.Is(err, db.ErrTokenNotFound):
				writeErr(w, http.StatusNotFound, "token not found")
			case errors.Is(err, db.ErrTokenAlreadyConsumed):
				writeErr(w, http.StatusGone, "token already consumed")
			default:
				writeErr(w, http.StatusInternalServerError, "consume token failed")
			}
			return
		}

		if err := database.SetPeerTargetUser(ctx, peerName, queryUser); err != nil {
			writeErr(w, http.StatusInternalServerError, "record target user failed")
			return
		}

		// Backfill the peer's dial address from the install-time source IP, but
		// only if enroll --address didn't already set one (SetPeerAddressIfEmpty).
		// X-Forwarded-For is deliberately NOT trusted (spoofable, and would record
		// the proxy/NAT gateway): proxied deployments should pass enroll --address.
		// A failure here is non-fatal — the address is a convenience and dialing
		// falls back to the peer name.
		if host, _, splitErr := net.SplitHostPort(r.RemoteAddr); splitErr == nil {
			_ = database.SetPeerAddressIfEmpty(ctx, peerName, host)
		} else if r.RemoteAddr != "" {
			_ = database.SetPeerAddressIfEmpty(ctx, peerName, r.RemoteAddr)
		}

		if tarball == nil {
			// Pre-upgrade token rows have no stored tarball. Such tokens must be
			// re-issued with the sign-at-mint enroll CLI.
			writeErr(w, http.StatusInternalServerError, "tarball not available")
			return
		}

		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(tarball)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(tarball)
	}
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
