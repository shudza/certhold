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
	"regexp"
	"strings"
	"testing"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/peerfiles"
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
	if err := d.SetMeta(context.Background(), db.MetaInstanceKey, testInstanceKey); err != nil {
		t.Fatalf("SetMeta instance_key: %v", err)
	}

	handler := New(d)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return &testEnv{srv: srv, db: d, ca: caObj}
}

// seedRootTarball builds a root-mode install tarball signed by the env's CA and
// returns its bytes, mirroring what the enroll CLI stores against the token row.
func (e *testEnv) seedRootTarball(t *testing.T, name string, groups []string) []byte {
	t.Helper()
	priv, _, pub, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	certBytes, _, err := e.ca.SignCert(ca.SignOptions{
		Pubkey:     pub,
		KeyID:      name,
		Principals: append([]string{name}, groups...),
	})
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	caPubLine := string(bytes.TrimRight(e.ca.PublicKeyAuthorizedKey(), "\n"))
	tb, err := peerfiles.Build(peerfiles.PeerFiles{
		Hostname:           name,
		PrivKey:            priv,
		CertPub:            certBytes,
		CAPub:              e.ca.PublicKeyAuthorizedKey(),
		AuthPrincipalsRoot: groups,
		CAKnownHostsEntry:  "@cert-authority certhold.test " + caPubLine,
	})
	if err != nil {
		t.Fatalf("peerfiles.Build: %v", err)
	}
	return tb
}

// seedUserTarball builds a user-mode install tarball signed by the env's CA.
func (e *testEnv) seedUserTarball(t *testing.T, name, targetUser string, groups []string) []byte {
	t.Helper()
	priv, _, pub, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	certBytes, _, err := e.ca.SignCert(ca.SignOptions{
		Pubkey:     pub,
		KeyID:      name,
		Principals: append([]string{name}, groups...),
	})
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	tb, err := peerfiles.BuildUser(peerfiles.UserPeerFiles{
		TargetUser: targetUser,
		PrivKey:    priv,
		CertPub:    certBytes,
		CAPub:      e.ca.PublicKeyAuthorizedKey(),
		Principals: groups,
	})
	if err != nil {
		t.Fatalf("peerfiles.BuildUser: %v", err)
	}
	return tb
}

// seedPeerRow inserts the peer row the byte-server expects so SetPeerTargetUser
// and GetPeer work. The token row carrying groups/tarball is seeded separately
// by each test via InsertTokenWithMode.
const testInstanceKey = "0123456789abcdef"

// seedPeerRow inserts a legacy v1 peer row (the layout selects the script the
// handler renders). seedPeerRowV2 inserts a layout-v2 row.
func (e *testEnv) seedPeerRow(t *testing.T, name, mode, targetUser string) {
	t.Helper()
	e.seedPeerRowLayout(t, name, mode, targetUser, peerfiles.LayoutV1)
}

func (e *testEnv) seedPeerRowV2(t *testing.T, name, mode, targetUser string) {
	t.Helper()
	e.seedPeerRowLayout(t, name, mode, targetUser, peerfiles.LayoutV2)
}

func (e *testEnv) seedPeerRowLayout(t *testing.T, name, mode, targetUser string, layout int) {
	t.Helper()
	ctx := context.Background()
	if err := e.db.InsertPeerWithMode(ctx, name, 1, "fp-"+name, []byte("authk-"+name), mode, targetUser, layout); err != nil {
		t.Fatalf("InsertPeerWithMode: %v", err)
	}
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

// newRemoteAddrServer wraps the enroll handler so every request presents a
// fixed RemoteAddr. httptest's own client connects over loopback, so to assert a
// deterministic source IP for the install-time backfill we override RemoteAddr in
// a wrapper rather than depend on the OS-assigned ephemeral loopback port.
func newRemoteAddrServer(t *testing.T, d *db.DB, remoteAddr string) *httptest.Server {
	t.Helper()
	inner := New(d)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = remoteAddr
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestEnrollBackfillsAddressFromRemoteAddr(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	srv := newRemoteAddrServer(t, env.db, "203.0.113.7:54321")

	const tok = "tok-backfill"
	tb := env.seedRootTarball(t, "vmBF", []string{"infra"})
	env.seedPeerRow(t, "vmBF", db.ModeRoot, "")
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmBF", "infra", db.ModeRoot, "", tb); err != nil {
		t.Fatalf("InsertTokenWithMode: %v", err)
	}

	resp, err := http.Get(srv.URL + "/enroll/" + tok)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	peer, err := env.db.GetPeer(ctx, "vmBF")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if peer.Address != "203.0.113.7" {
		t.Errorf("Address = %q, want 203.0.113.7 (host of RemoteAddr)", peer.Address)
	}
}

func TestEnrollDoesNotOverwriteExplicitAddress(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	srv := newRemoteAddrServer(t, env.db, "203.0.113.7:54321")

	const tok = "tok-explicit-addr"
	tb := env.seedRootTarball(t, "vmEA", []string{"infra"})
	env.seedPeerRow(t, "vmEA", db.ModeRoot, "")
	// Simulate enroll --address: an explicit address already on the peer row.
	if err := env.db.SetPeerAddress(ctx, "vmEA", "vm.internal.example"); err != nil {
		t.Fatalf("SetPeerAddress: %v", err)
	}
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmEA", "infra", db.ModeRoot, "", tb); err != nil {
		t.Fatalf("InsertTokenWithMode: %v", err)
	}

	resp, err := http.Get(srv.URL + "/enroll/" + tok)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	peer, err := env.db.GetPeer(ctx, "vmEA")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if peer.Address != "vm.internal.example" {
		t.Errorf("Address = %q, want vm.internal.example (explicit address must not be overwritten)", peer.Address)
	}
}

func TestEnrollStreamsSeededTarball(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	const tok = "test-token-vm1"
	wantBytes := env.seedRootTarball(t, "vm1", []string{"infra", "databases"})
	env.seedPeerRow(t, "vm1", db.ModeRoot, "")
	if err := env.db.InsertTokenWithMode(ctx, tok, "vm1", "infra,databases", db.ModeRoot, "", wantBytes); err != nil {
		t.Fatalf("InsertTokenWithMode: %v", err)
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
	if !bytes.Equal(body, wantBytes) {
		t.Errorf("streamed bytes differ from seeded tarball (%d vs %d bytes)", len(body), len(wantBytes))
	}

	// The streamed bytes must still be a valid install tarball.
	entries := extractTarball(t, body)
	for _, name := range []string{
		"etc/ssh/peer_ed25519",
		"etc/ssh/peer_ed25519-cert.pub",
		"etc/ssh/ca.pub",
		"etc/ssh/auth_principals/root",
	} {
		if _, ok := entries[name]; !ok {
			t.Errorf("missing entry %q", name)
		}
	}

	// Re-fetch must 410 (token consumed; blob cleared inside ConsumeToken).
	resp2, err := http.Get(env.srv.URL + "/enroll/" + tok)
	if err != nil {
		t.Fatalf("re-fetch GET: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusGone {
		b, _ := io.ReadAll(resp2.Body)
		t.Errorf("re-fetch status = %d, want 410; body=%s", resp2.StatusCode, b)
	}
}

func TestEnrollTokenAlreadyConsumed(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	const tok = "tok-consume-twice"
	tb := env.seedRootTarball(t, "vm2", []string{"infra"})
	env.seedPeerRow(t, "vm2", db.ModeRoot, "")
	if err := env.db.InsertTokenWithMode(ctx, tok, "vm2", "infra", db.ModeRoot, "", tb); err != nil {
		t.Fatalf("InsertTokenWithMode: %v", err)
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
	tb := env.seedRootTarball(t, "vmS", []string{"infra"})
	env.seedPeerRow(t, "vmS", db.ModeRoot, "")
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmS", "infra", db.ModeRoot, "", tb); err != nil {
		t.Fatalf("InsertTokenWithMode: %v", err)
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
		"curl -kfsSL " + env.srv.URL + "/enroll/" + tok + " | tar -xzC /",
		"sed -i -E '/^# BEGIN certhold( v[0-9]+)?$/,/^# END certhold( v[0-9]+)?$/d' /etc/ssh/sshd_config",
		"cat >> /etc/ssh/sshd_config <<'SSHD_EOF'",
		"# BEGIN certhold v1",
		"# END certhold v1",
		"SSHD_EOF",
		"sed -i -E '/^# BEGIN certhold( v[0-9]+)?$/,/^# END certhold( v[0-9]+)?$/d' /etc/ssh/ssh_config",
		"cat >> /etc/ssh/ssh_config <<'SSH_EOF'",
		"SSH_EOF",
		"systemctl reload sshd",
		"HostKey /etc/ssh/peer_ed25519",
		"TrustedUserCAKeys /etc/ssh/ca.pub",
		"AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u",
		"CertificateFile /etc/ssh/peer_ed25519-cert.pub",
		"UserKnownHostsFile /etc/ssh/ca_known_hosts",
		// Feature 3 peer-side passphrase block.
		`KEY=/etc/ssh/peer_ed25519`,
		`if [ "${CERTHOLD_NO_PASSPHRASE:-}" != "1" ]; then`,
		`PASS="${CERTHOLD_KEY_PASSPHRASE:-}"`,
		`if [ -z "$PASS" ] && [ -e /dev/tty ]; then`,
		`ssh-keygen -p -f "$KEY"`,
	}
	for _, s := range mustContain {
		if !strings.Contains(bodyStr, s) {
			t.Errorf("script body missing %q\nbody:\n%s", s, bodyStr)
		}
	}
	// The passphrase block must run before the sshd reload.
	if idxBlock, idxReload := strings.Index(bodyStr, `ssh-keygen -p -f "$KEY"`), strings.Index(bodyStr, "systemctl reload sshd"); idxBlock < 0 || idxReload < 0 || idxBlock > idxReload {
		t.Errorf("passphrase block (%d) must precede systemctl reload sshd (%d)", idxBlock, idxReload)
	}

	// The sed ERE matches both the legacy bare sentinel and any versioned one.
	beginRe := regexp.MustCompile(`^# BEGIN certhold( v[0-9]+)?$`)
	for _, line := range []string{"# BEGIN certhold", "# BEGIN certhold v1"} {
		if !beginRe.MatchString(line) {
			t.Errorf("begin sentinel regex did not match %q", line)
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
	tb := env.seedRootTarball(t, "vmSC", []string{"infra"})
	env.seedPeerRow(t, "vmSC", db.ModeRoot, "")
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmSC", "infra", db.ModeRoot, "", tb); err != nil {
		t.Fatalf("InsertTokenWithMode: %v", err)
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
	tb := env.seedUserTarball(t, "vmU", "alice", []string{"infra", "databases"})
	env.seedPeerRow(t, "vmU", db.ModeUser, "alice")
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmU", "infra,databases", db.ModeUser, "alice", tb); err != nil {
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
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmU", "infra", db.ModeUser, "bob", nil); err != nil {
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
		`curl -kfsSL ` + env.srv.URL + `/enroll/` + tok + `?user=$TARGET_USER | tar -xzC "$USER_HOME/.ssh"`,
		`chmod 600 "$USER_HOME/.ssh/id_ed25519"`,
		// Feature 3 peer-side passphrase block (user-mode key path).
		`KEY="$USER_HOME/.ssh/id_ed25519"`,
		`if [ "${CERTHOLD_NO_PASSPHRASE:-}" != "1" ]; then`,
		`PASS="${CERTHOLD_KEY_PASSPHRASE:-}"`,
		`if [ -z "$PASS" ] && [ -e /dev/tty ]; then`,
		`ssh-keygen -p -f "$KEY"`,
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
	tb := env.seedUserTarball(t, "vmNP", "alice", []string{"infra"})
	env.seedPeerRow(t, "vmNP", db.ModeUser, "")
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmNP", "infra", db.ModeUser, "", tb); err != nil {
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
	tb := env.seedUserTarball(t, "vmNQ", "bob", []string{"infra"})
	env.seedPeerRow(t, "vmNQ", db.ModeUser, "")
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmNQ", "infra", db.ModeUser, "", tb); err != nil {
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
	tb := env.seedUserTarball(t, "vmIQ", "alice", []string{"infra"})
	env.seedPeerRow(t, "vmIQ", db.ModeUser, "")
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmIQ", "infra", db.ModeUser, "", tb); err != nil {
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
	tb := env.seedUserTarball(t, "vmM", "bob", []string{"infra"})
	env.seedPeerRow(t, "vmM", db.ModeUser, "bob")
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmM", "infra", db.ModeUser, "bob", tb); err != nil {
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
	tb := env.seedUserTarball(t, "vmX", "bob", []string{"infra"})
	env.seedPeerRow(t, "vmX", db.ModeUser, "bob")
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmX", "infra", db.ModeUser, "bob", tb); err != nil {
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
	tb := env.seedRootTarball(t, "vmR", []string{"infra"})
	env.seedPeerRow(t, "vmR", db.ModeRoot, "")
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmR", "infra", db.ModeRoot, "", tb); err != nil {
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

func TestEnrollNullTarball500(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	const tok = "tok-null-tarball"
	// Pre-upgrade token: a row with no stored tarball (NULL blob).
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmNull", "infra", db.ModeRoot, "", nil); err != nil {
		t.Fatalf("InsertTokenWithMode: %v", err)
	}
	resp, err := http.Get(env.srv.URL + "/enroll/" + tok)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", resp.StatusCode, body)
	}
	var payload map[string]string
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload["error"] != "tarball not available" {
		t.Errorf("error = %q, want 'tarball not available'", payload["error"])
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

// TestEnrollV2Root_Script asserts the layout-v2 root install script: appends the
// authorized_keys cert-authority line guarded by a grep, splices the keyed
// ~/.ssh/config with the keyed version-agnostic sed, runs the legacy sshd
// cleanup against both global configs and reloads sshd once, and carries NONE of
// the host-level certhold directives.
func TestEnrollV2Root_Script(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	const tok = "tok-v2-root"
	env.seedPeerRowV2(t, "vmV2R", db.ModeRoot, "")
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmV2R", "infra", db.ModeRoot, "", []byte("tb")); err != nil {
		t.Fatalf("InsertTokenWithMode: %v", err)
	}
	resp, err := http.Get(env.srv.URL + "/enroll/" + tok + ".sh")
	if err != nil {
		t.Fatalf("GET .sh: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d; body=%s", resp.StatusCode, b)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)

	mustContain := []string{
		"#!/usr/bin/env bash",
		"USER_HOME=/root",
		`mkdir -p "$USER_HOME/.ssh"`,
		`install -m 600 "$STAGE/id_ed25519_` + testInstanceKey + `" "$USER_HOME/.ssh/id_ed25519_` + testInstanceKey + `"`,
		// grep-guarded idempotent authorized_keys append.
		`CA_KEY="$(awk '{print $3}' "$STAGE/ca_authorized_keys")"`,
		`if ! grep -qF "$CA_KEY" "$USER_HOME/.ssh/authorized_keys"; then cat "$STAGE/ca_authorized_keys" >> "$USER_HOME/.ssh/authorized_keys"; fi`,
		// keyed, version-agnostic sed splice of ~/.ssh/config.
		`sed -i -E "/^# BEGIN certhold ` + testInstanceKey + `( v[0-9]+)?\$/,/^# END certhold ` + testInstanceKey + `( v[0-9]+)?\$/d" "$USER_HOME/.ssh/config"`,
		"# BEGIN certhold " + testInstanceKey + " v2",
		"# END certhold " + testInstanceKey + " v2",
		// legacy sshd cleanup against both global configs + single reload.
		`sed -i -E '/^# BEGIN certhold( v[0-9]+)?$/,/^# END certhold( v[0-9]+)?$/d' /etc/ssh/sshd_config`,
		`sed -i -E '/^# BEGIN certhold( v[0-9]+)?$/,/^# END certhold( v[0-9]+)?$/d' /etc/ssh/ssh_config`,
		"systemctl reload sshd",
	}
	for _, m := range mustContain {
		if !strings.Contains(s, m) {
			t.Errorf("v2 root script missing %q\nfull:\n%s", m, s)
		}
	}

	for _, forbidden := range []string{"TrustedUserCAKeys", "AuthorizedPrincipalsFile", "RevokedKeys", "HostCertificate", "auth_principals", "/etc/ssh/peer_ed25519"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("v2 root script must NOT contain %q\nfull:\n%s", forbidden, s)
		}
	}

	if got := strings.Count(s, "systemctl reload sshd"); got != 1 {
		t.Errorf("expected exactly one sshd reload, got %d", got)
	}
}

func TestEnrollV2User_Script(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	const tok = "tok-v2-user"
	env.seedPeerRowV2(t, "vmV2U", db.ModeUser, "alice")
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmV2U", "infra", db.ModeUser, "alice", []byte("tb")); err != nil {
		t.Fatalf("InsertTokenWithMode: %v", err)
	}
	resp, err := http.Get(env.srv.URL + "/enroll/" + tok + ".sh")
	if err != nil {
		t.Fatalf("GET .sh: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)

	mustContain := []string{
		`TARGET_USER="$(id -un)"`,
		`USER_HOME="$HOME"`,
		`curl -kfsSL ` + env.srv.URL + `/enroll/` + tok + `?user=$TARGET_USER | tar -xzC "$STAGE"`,
		"# BEGIN certhold " + testInstanceKey + " v2",
	}
	for _, m := range mustContain {
		if !strings.Contains(s, m) {
			t.Errorf("v2 user script missing %q\nfull:\n%s", m, s)
		}
	}
	// v2 user mode must NOT touch global sshd configs or reload.
	for _, forbidden := range []string{"systemctl reload sshd", "/etc/ssh/sshd_config", "/etc/ssh/ssh_config"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("v2 user script must NOT contain %q\nfull:\n%s", forbidden, s)
		}
	}
}

// TestEnrollV1Root_LegacyScriptUnchanged keeps an explicit assertion that a v1
// (legacy) root token still renders the host-level splice script.
func TestEnrollV1Root_LegacyScriptUnchanged(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	const tok = "tok-v1-legacy"
	env.seedPeerRow(t, "vmV1", db.ModeRoot, "") // v1
	if err := env.db.InsertTokenWithMode(ctx, tok, "vmV1", "infra", db.ModeRoot, "", []byte("tb")); err != nil {
		t.Fatalf("InsertTokenWithMode: %v", err)
	}
	resp, err := http.Get(env.srv.URL + "/enroll/" + tok + ".sh")
	if err != nil {
		t.Fatalf("GET .sh: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	for _, m := range []string{
		"TrustedUserCAKeys /etc/ssh/ca.pub",
		"AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u",
		"# BEGIN certhold v1",
		"KEY=/etc/ssh/peer_ed25519",
	} {
		if !strings.Contains(s, m) {
			t.Errorf("legacy v1 root script missing %q\nfull:\n%s", m, s)
		}
	}
}
