// Package httpserver exposes the enrollment HTTP endpoint used during peer onboarding.
package httpserver

import (
	"encoding/json"
	"errors"
	"fmt"
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
		_, _, mode, _, consumed, err := database.LookupToken(r.Context(), token)
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
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
			scheme = p
		}
		baseURL := fmt.Sprintf("%s://%s", scheme, r.Host)
		var body string
		if mode == db.ModeUser {
			body = fmt.Sprintf(`#!/usr/bin/env bash
set -e
TARGET_USER="$(id -un)"
USER_HOME="$HOME"
[ -n "$USER_HOME" ] || { echo "no \$HOME" >&2; exit 1; }
mkdir -p "$USER_HOME/.ssh"
chmod 700 "$USER_HOME/.ssh"
curl -kfsSL %s/enroll/%s?user=$TARGET_USER | tar -xzC "$USER_HOME/.ssh"
chmod 600 "$USER_HOME/.ssh/id_ed25519"
KEY="$USER_HOME/.ssh/id_ed25519"
%s`, baseURL, token, peerPassphraseBlock)
		} else {
			body = fmt.Sprintf(`#!/usr/bin/env bash
set -e

curl -kfsSL %s/enroll/%s | tar -xzC /

KEY=/etc/ssh/peer_ed25519
%s
sed -i -E '/^# BEGIN certhold( v[0-9]+)?$/,/^# END certhold( v[0-9]+)?$/d' /etc/ssh/sshd_config
cat >> /etc/ssh/sshd_config <<'SSHD_EOF'
%sSSHD_EOF

sed -i -E '/^# BEGIN certhold( v[0-9]+)?$/,/^# END certhold( v[0-9]+)?$/d' /etc/ssh/ssh_config
cat >> /etc/ssh/ssh_config <<'SSH_EOF'
%sSSH_EOF

systemctl reload sshd
`, baseURL, token, peerPassphraseBlock, peerfiles.SshdBlock(peerfiles.CurrentLayout), peerfiles.SshClientBlock(peerfiles.CurrentLayout))
		}
		w.Header().Set("Content-Type", "application/x-shellscript; charset=utf-8")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}
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
		_, _, preMode, preTargetUser, preConsumed, err := database.LookupToken(ctx, token)
		if err != nil {
			if errors.Is(err, db.ErrTokenNotFound) {
				writeErr(w, http.StatusNotFound, "token not found")
				return
			}
			writeErr(w, http.StatusInternalServerError, "lookup token failed")
			return
		}
		if !preConsumed && preMode == db.ModeUser {
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

		peerName, _, mode, _, tarball, err := database.ConsumeToken(ctx, token)
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

		if mode == db.ModeUser {
			if err := database.SetPeerTargetUser(ctx, peerName, queryUser); err != nil {
				writeErr(w, http.StatusInternalServerError, "record target user failed")
				return
			}
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
