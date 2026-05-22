package httpserver

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
)

type testEnv struct {
	srv *httptest.Server
	db  *db.DB
	ca  *ca.CA
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()
	tempDir := t.TempDir()
	caObj, err := ca.Generate(filepath.Join(tempDir, "ca"))
	if err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	d, err := db.Open(filepath.Join(tempDir, "state.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	handler := New(d, caObj, "certhold.test")
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return &testEnv{srv: srv, db: d, ca: caObj}
}

func extractTarball(t *testing.T, body []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		out[hdr.Name] = data
	}
	return out
}

func TestEnrollSuccess(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	const tok = "test-token-vm1"
	if err := env.db.InsertToken(ctx, tok, "vm1", "infra,databases"); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}

	resp, err := http.Get(env.srv.URL + "/enroll/" + tok)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/gzip" {
		t.Errorf("Content-Type = %q, want application/gzip", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	entries := extractTarball(t, body)

	expectedNames := []string{
		"etc/ssh/peer_ed25519",
		"etc/ssh/peer_ed25519-cert.pub",
		"etc/ssh/ca.pub",
		"etc/ssh/krl",
		"etc/ssh/auth_principals/root",
		"etc/ssh/ca_known_hosts",
	}
	for _, name := range expectedNames {
		if _, ok := entries[name]; !ok {
			t.Errorf("missing entry %q", name)
		}
	}
	for _, forbidden := range []string{
		"etc/ssh/sshd_config.d/certhold.conf",
		"etc/ssh/ssh_config.d/certhold.conf",
	} {
		if _, ok := entries[forbidden]; ok {
			t.Errorf("forbidden entry present: %q", forbidden)
		}
	}
	if len(entries) != 6 {
		t.Errorf("entry count: got %d want 6", len(entries))
	}

	certBytes := entries["etc/ssh/peer_ed25519-cert.pub"]
	pk, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed key is not *ssh.Certificate: %T", pk)
	}
	if cert.KeyId != "vm1" {
		t.Errorf("KeyId = %q, want vm1", cert.KeyId)
	}
	wantPrincipals := []string{"vm1", "infra", "databases"}
	if !reflect.DeepEqual(cert.ValidPrincipals, wantPrincipals) {
		t.Errorf("ValidPrincipals = %v, want %v", cert.ValidPrincipals, wantPrincipals)
	}

	caPub, _, _, _, err := ssh.ParseAuthorizedKey(env.ca.PublicKeyAuthorizedKey())
	if err != nil {
		t.Fatalf("parse CA pub: %v", err)
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) {
		t.Error("cert.SignatureKey does not match CA public key")
	}

	caKnownHosts := string(entries["etc/ssh/ca_known_hosts"])
	if !bytes.HasPrefix([]byte(caKnownHosts), []byte("@cert-authority certhold.test ")) {
		t.Errorf("ca_known_hosts unexpected prefix: %q", caKnownHosts)
	}

	authPrincipals := string(entries["etc/ssh/auth_principals/root"])
	if want := "manager\ninfra\ndatabases\n"; authPrincipals != want {
		t.Errorf("auth_principals/root = %q, want %q", authPrincipals, want)
	}

	peer, err := env.db.GetPeer(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if peer.Serial != cert.Serial {
		t.Errorf("peer.Serial = %d, want %d", peer.Serial, cert.Serial)
	}

	gs, err := env.db.GetPeerGroups(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeerGroups: %v", err)
	}
	if !reflect.DeepEqual(gs, []string{"databases", "infra"}) {
		t.Errorf("peer groups = %v, want [databases infra]", gs)
	}

	as, err := env.db.GetPeerAllowedGroups(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	if !reflect.DeepEqual(as, []string{"databases", "infra"}) {
		t.Errorf("peer allowed groups = %v, want [databases infra]", as)
	}
}

func TestEnrollTokenAlreadyConsumed(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	const tok = "tok-consume-twice"
	if err := env.db.InsertToken(ctx, tok, "vm2", "infra"); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}

	resp1, err := http.Get(env.srv.URL + "/enroll/" + tok)
	if err != nil {
		t.Fatalf("first GET: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp1.Body)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d, want 200", resp1.StatusCode)
	}

	resp2, err := http.Get(env.srv.URL + "/enroll/" + tok)
	if err != nil {
		t.Fatalf("second GET: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusGone {
		body, _ := io.ReadAll(resp2.Body)
		t.Errorf("second status = %d, want 410; body=%s", resp2.StatusCode, body)
	}
	if ct := resp2.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var payload map[string]string
	if err := json.NewDecoder(resp2.Body).Decode(&payload); err != nil {
		t.Errorf("decode JSON error body: %v", err)
	}
	if payload["error"] == "" {
		t.Errorf("error field missing: %v", payload)
	}
}

func TestEnrollUnknownToken(t *testing.T) {
	env := setupTestEnv(t)

	resp, err := http.Get(env.srv.URL + "/enroll/does-not-exist")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want 404; body=%s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var payload map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Errorf("decode JSON error body: %v", err)
	}
	if payload["error"] == "" {
		t.Errorf("error field missing: %v", payload)
	}
}

func TestEnrollScriptSuccess(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	const tok = "tok-script-ok"
	if err := env.db.InsertToken(ctx, tok, "vmS", "infra"); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}

	resp, err := http.Get(env.srv.URL + "/enroll/" + tok + ".sh")
	if err != nil {
		t.Fatalf("GET .sh: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-shellscript; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	bodyStr := string(body)
	mustContain := []string{
		"#!/usr/bin/env bash",
		"set -e",
		"curl -fsSL " + env.srv.URL + "/enroll/" + tok + " | tar -xzC /",
		"sed -i '/^# BEGIN certhold$/,/^# END certhold$/d' /etc/ssh/sshd_config",
		"cat >> /etc/ssh/sshd_config <<'SSHD_EOF'",
		"# BEGIN certhold",
		"# END certhold",
		"SSHD_EOF",
		"sed -i '/^# BEGIN certhold$/,/^# END certhold$/d' /etc/ssh/ssh_config",
		"cat >> /etc/ssh/ssh_config <<'SSH_EOF'",
		"SSH_EOF",
		"systemctl reload sshd",
		"HostKey /etc/ssh/peer_ed25519",
		"TrustedUserCAKeys /etc/ssh/ca.pub",
		"AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u",
		"CertificateFile /etc/ssh/peer_ed25519-cert.pub",
		"UserKnownHostsFile /etc/ssh/ca_known_hosts",
	}
	for _, s := range mustContain {
		if !strings.Contains(bodyStr, s) {
			t.Errorf("script body missing %q\nbody:\n%s", s, bodyStr)
		}
	}

	resp2, err := http.Get(env.srv.URL + "/enroll/" + tok)
	if err != nil {
		t.Fatalf("GET tarball: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("tarball status = %d after .sh fetch, want 200; body=%s", resp2.StatusCode, b)
	}
}

func TestEnrollScriptUnknownToken(t *testing.T) {
	env := setupTestEnv(t)
	resp, err := http.Get(env.srv.URL + "/enroll/nope.sh")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want 404; body=%s", resp.StatusCode, body)
	}
}

func TestEnrollScriptConsumedToken(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	const tok = "tok-script-consumed"
	if err := env.db.InsertToken(ctx, tok, "vmSC", "infra"); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}
	resp1, err := http.Get(env.srv.URL + "/enroll/" + tok)
	if err != nil {
		t.Fatalf("GET tarball: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp1.Body)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("tarball status = %d, want 200", resp1.StatusCode)
	}

	resp2, err := http.Get(env.srv.URL + "/enroll/" + tok + ".sh")
	if err != nil {
		t.Fatalf("GET .sh: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusGone {
		body, _ := io.ReadAll(resp2.Body)
		t.Errorf("status = %d, want 410; body=%s", resp2.StatusCode, body)
	}
}

func TestEnrollUserMode_Tarball(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	const tok = "tok-user-vm"
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmU", "infra,databases", db.ModeUser, "alice"); err != nil {
		t.Fatalf("InsertTokenWithMode: %v", err)
	}
	resp, err := http.Get(env.srv.URL + "/enroll/" + tok + "?user=alice")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d; body=%s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	entries := extractTarball(t, body)
	wantNames := []string{"id_ed25519", "id_ed25519-cert.pub", "authorized_keys", "known_hosts", "config"}
	if len(entries) != 5 {
		t.Errorf("user-mode tarball entries = %d, want 5: %v", len(entries), entries)
	}
	for _, n := range wantNames {
		if _, ok := entries[n]; !ok {
			t.Errorf("missing entry %q", n)
		}
	}
	for n := range entries {
		if strings.HasPrefix(n, "etc/") || strings.HasPrefix(n, "/") {
			t.Errorf("user-mode entry has root path %q", n)
		}
	}
	ak := string(entries["authorized_keys"])
	if !strings.HasPrefix(ak, `cert-authority,principals="manager,infra,databases" `) {
		t.Errorf("authorized_keys wrong: %q", ak)
	}
	peer, err := env.db.GetPeer(ctx, "vmU")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if peer.Mode != db.ModeUser || peer.TargetUser != "alice" {
		t.Errorf("peer.Mode=%q peer.TargetUser=%q", peer.Mode, peer.TargetUser)
	}
}

func TestEnrollUserMode_Script(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	const tok = "tok-user-script"
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmU", "infra", db.ModeUser, "bob"); err != nil {
		t.Fatalf("InsertTokenWithMode: %v", err)
	}
	resp, err := http.Get(env.srv.URL + "/enroll/" + tok + ".sh")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d; body=%s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	mustContain := []string{
		`TARGET_USER="$(id -un)"`,
		`USER_HOME="$HOME"`,
		`mkdir -p "$USER_HOME/.ssh"`,
		`chmod 700 "$USER_HOME/.ssh"`,
		`curl -fsSL ` + env.srv.URL + `/enroll/` + tok + `?user=$TARGET_USER | tar -xzC "$USER_HOME/.ssh"`,
		`chmod 600 "$USER_HOME/.ssh/id_ed25519"`,
	}
	for _, m := range mustContain {
		if !strings.Contains(s, m) {
			t.Errorf("script missing %q\nfull:\n%s", m, s)
		}
	}
	for _, forbidden := range []string{"systemctl reload sshd", "/etc/ssh/sshd_config", "BEGIN certhold", "getent passwd", "chown"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("user-mode script should not contain %q\nfull:\n%s", forbidden, s)
		}
	}
}

func TestEnrollUserMode_NoPresetValidQuery(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	const tok = "tok-up-noprese"
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmNP", "infra", db.ModeUser, ""); err != nil {
		t.Fatalf("InsertTokenWithMode: %v", err)
	}
	resp, err := http.Get(env.srv.URL + "/enroll/" + tok + "?user=alice")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d; body=%s", resp.StatusCode, body)
	}
	peer, err := env.db.GetPeer(ctx, "vmNP")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if peer.TargetUser != "alice" {
		t.Errorf("peer.TargetUser = %q, want alice", peer.TargetUser)
	}
	resp2, err := http.Get(env.srv.URL + "/enroll/" + tok + "?user=alice")
	if err != nil {
		t.Fatalf("second GET: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusGone {
		t.Errorf("second status = %d, want 410", resp2.StatusCode)
	}
}

func TestEnrollUserMode_NoPresetMissingQuery(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	const tok = "tok-up-noquery"
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmNQ", "infra", db.ModeUser, ""); err != nil {
		t.Fatalf("InsertTokenWithMode: %v", err)
	}
	resp, err := http.Get(env.srv.URL + "/enroll/" + tok)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
	var payload map[string]string
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload["error"] != "user required" {
		t.Errorf("error = %q, want 'user required'", payload["error"])
	}
	resp2, err := http.Get(env.srv.URL + "/enroll/" + tok + "?user=bob")
	if err != nil {
		t.Fatalf("retry GET: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("retry status = %d, want 200; body=%s", resp2.StatusCode, b)
	}
}

func TestEnrollUserMode_InvalidQuery(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	const tok = "tok-up-invalid"
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmIQ", "infra", db.ModeUser, ""); err != nil {
		t.Fatalf("InsertTokenWithMode: %v", err)
	}
	resp, err := http.Get(env.srv.URL + "/enroll/" + tok + "?user=Has%20Space")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	resp2, err := http.Get(env.srv.URL + "/enroll/" + tok + "?user=alice")
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("retry status = %d, want 200; body=%s", resp2.StatusCode, b)
	}
}

func TestEnrollUserMode_PresetMatching(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	const tok = "tok-up-match"
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmM", "infra", db.ModeUser, "bob"); err != nil {
		t.Fatalf("InsertTokenWithMode: %v", err)
	}
	resp, err := http.Get(env.srv.URL + "/enroll/" + tok + "?user=bob")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, b)
	}
	peer, err := env.db.GetPeer(ctx, "vmM")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if peer.TargetUser != "bob" {
		t.Errorf("peer.TargetUser = %q, want bob", peer.TargetUser)
	}
}

func TestEnrollUserMode_PresetMismatch(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	const tok = "tok-up-mismatch"
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmX", "infra", db.ModeUser, "bob"); err != nil {
		t.Fatalf("InsertTokenWithMode: %v", err)
	}
	resp, err := http.Get(env.srv.URL + "/enroll/" + tok + "?user=eve")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
	var payload map[string]string
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload["error"] != "user mismatch" {
		t.Errorf("error = %q, want 'user mismatch'", payload["error"])
	}
	resp2, err := http.Get(env.srv.URL + "/enroll/" + tok + "?user=bob")
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("retry status = %d, want 200 (token must be preserved on mismatch); body=%s", resp2.StatusCode, b)
	}
}

func TestEnrollRootMode_IgnoresUserQuery(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	const tok = "tok-root-userq"
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmR", "infra", db.ModeRoot, ""); err != nil {
		t.Fatalf("InsertTokenWithMode: %v", err)
	}
	resp, err := http.Get(env.srv.URL + "/enroll/" + tok + "?user=anything")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, b)
	}
	peer, err := env.db.GetPeer(ctx, "vmR")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if peer.Mode != db.ModeRoot {
		t.Errorf("peer.Mode = %q, want root", peer.Mode)
	}
	if peer.TargetUser != "" {
		t.Errorf("peer.TargetUser = %q, want empty for root mode", peer.TargetUser)
	}
}

func TestEnrollMethodNotAllowed(t *testing.T) {
	env := setupTestEnv(t)
	req, err := http.NewRequest(http.MethodPost, env.srv.URL+"/enroll/whatever", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("POST status = %d, want non-2xx", resp.StatusCode)
	}
}
