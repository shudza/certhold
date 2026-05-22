// Package httpserver exposes the enrollment HTTP endpoint used during peer onboarding.
package httpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/peerfiles"
)

func New(database *db.DB, caObj *ca.CA, hostname string) http.Handler {
	mux := http.NewServeMux()
	tarball := enrollHandler(database, caObj, hostname)
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
		_, _, consumed, err := database.LookupToken(r.Context(), token)
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
		body := fmt.Sprintf(`#!/usr/bin/env bash
set -e

curl -fsSL %s/enroll/%s | tar -xzC /

sed -i '/^# BEGIN certhold$/,/^# END certhold$/d' /etc/ssh/sshd_config
cat >> /etc/ssh/sshd_config <<'SSHD_EOF'
%sSSHD_EOF

sed -i '/^# BEGIN certhold$/,/^# END certhold$/d' /etc/ssh/ssh_config
cat >> /etc/ssh/ssh_config <<'SSH_EOF'
%sSSH_EOF

systemctl reload sshd
`, baseURL, token, peerfiles.SshdBlockContents, peerfiles.SshClientBlockContents)
		w.Header().Set("Content-Type", "application/x-shellscript; charset=utf-8")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}
}

func enrollHandler(database *db.DB, caObj *ca.CA, hostname string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		token := r.PathValue("token")
		if token == "" {
			writeErr(w, http.StatusBadRequest, "missing token")
			return
		}

		peerName, groupsCSV, err := database.ConsumeToken(ctx, token)
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

		groups := parseGroupsCSV(groupsCSV)

		principals := make([]string, 0, 1+len(groups))
		principals = append(principals, peerName)
		principals = append(principals, groups...)

		priv, pubAuth, sshPub, err := ca.GeneratePeerKey()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "generate peer key failed")
			return
		}

		certBytes, serial, err := caObj.SignCert(ca.SignOptions{
			Pubkey:     sshPub,
			KeyID:      peerName,
			Principals: principals,
		})
		if err != nil {
			zero(priv)
			writeErr(w, http.StatusInternalServerError, "sign cert failed")
			return
		}

		fingerprint := ssh.FingerprintSHA256(sshPub)

		if err := database.InsertPeer(ctx, peerName, serial, fingerprint, pubAuth); err != nil {
			zero(priv)
			writeErr(w, http.StatusInternalServerError, "insert peer failed")
			return
		}
		for _, g := range groups {
			if err := database.EnsureGroup(ctx, g); err != nil {
				zero(priv)
				writeErr(w, http.StatusInternalServerError, "ensure group failed")
				return
			}
		}
		if err := database.SetPeerGroups(ctx, peerName, groups); err != nil {
			zero(priv)
			writeErr(w, http.StatusInternalServerError, "set peer groups failed")
			return
		}
		if err := database.SetPeerAllowedGroups(ctx, peerName, groups); err != nil {
			zero(priv)
			writeErr(w, http.StatusInternalServerError, "set peer allowed groups failed")
			return
		}

		caPubLine := string(bytes.TrimRight(caObj.PublicKeyAuthorizedKey(), "\n"))
		caKnownHostsEntry := "@cert-authority " + hostname + " " + caPubLine

		tarball, err := peerfiles.Build(peerfiles.PeerFiles{
			Hostname:           peerName,
			PrivKey:            priv,
			CertPub:            certBytes,
			CAPub:              caObj.PublicKeyAuthorizedKey(),
			KRL:                nil,
			AuthPrincipalsRoot: groups,
			CAKnownHostsEntry:  caKnownHostsEntry,
		})
		if err != nil {
			zero(priv)
			writeErr(w, http.StatusInternalServerError, "build tarball failed")
			return
		}

		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(tarball)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(tarball)

		zero(priv)
	}
}

func parseGroupsCSV(csv string) []string {
	var out []string
	for _, raw := range strings.Split(csv, ",") {
		g := strings.TrimSpace(raw)
		if g == "" {
			continue
		}
		out = append(out, g)
	}
	return out
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
