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
	"os"
	"os/exec"
	"path/filepath"
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
		TargetUser:  targetUser,
		PrivKey:     priv,
		CertPub:     certBytes,
		CAPub:       e.ca.PublicKeyAuthorizedKey(),
		Principals:  groups,
		InstanceKey: testInstanceKey,
	})
	if err != nil {
		t.Fatalf("peerfiles.BuildUser: %v", err)
	}
	return tb
}

const testInstanceKey = "0123456789abcdef"

// seedPeerRow inserts the layout-v2 user-mode peer row the byte-server expects
// so SetPeerTargetUser and GetPeer work. The token row carrying groups/tarball
// is seeded separately by each test via InsertToken.
func (e *testEnv) seedPeerRow(t *testing.T, name, targetUser string) {
	t.Helper()
	ctx := context.Background()
	if err := e.db.InsertPeer(ctx, name, 1, "fp-"+name, []byte("authk-"+name), targetUser); err != nil {
		t.Fatalf("InsertPeer: %v", err)
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
	tb := env.seedUserTarball(t, "vmBF", "alice", []string{"infra"})
	env.seedPeerRow(t, "vmBF", "alice")
	if err := env.db.InsertToken(ctx, tok, "vmBF", "infra", "alice", tb); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}

	resp, err := http.Get(srv.URL + "/enroll/" + tok + "?user=alice")
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
	tb := env.seedUserTarball(t, "vmEA", "alice", []string{"infra"})
	env.seedPeerRow(t, "vmEA", "alice")
	// Simulate enroll --address: an explicit address already on the peer row.
	if err := env.db.SetPeerAddress(ctx, "vmEA", "vm.internal.example"); err != nil {
		t.Fatalf("SetPeerAddress: %v", err)
	}
	if err := env.db.InsertToken(ctx, tok, "vmEA", "infra", "alice", tb); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}

	resp, err := http.Get(srv.URL + "/enroll/" + tok + "?user=alice")
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
	wantBytes := env.seedUserTarball(t, "vm1", "alice", []string{"infra", "databases"})
	env.seedPeerRow(t, "vm1", "alice")
	if err := env.db.InsertToken(ctx, tok, "vm1", "infra,databases", "alice", wantBytes); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}

	resp, err := http.Get(env.srv.URL + "/enroll/" + tok + "?user=alice")
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

	// The streamed bytes must still be a valid user-mode install tarball.
	entries := extractTarball(t, body)
	for _, name := range []string{
		"id_ed25519_" + testInstanceKey,
		"id_ed25519_" + testInstanceKey + "-cert.pub",
		"ca_authorized_keys",
		"config",
	} {
		if _, ok := entries[name]; !ok {
			t.Errorf("missing entry %q", name)
		}
	}

	// Re-fetch must 410 (token consumed; blob cleared inside ConsumeToken).
	resp2, err := http.Get(env.srv.URL + "/enroll/" + tok + "?user=alice")
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
	tb := env.seedUserTarball(t, "vm2", "alice", []string{"infra"})
	env.seedPeerRow(t, "vm2", "alice")
	if err := env.db.InsertToken(ctx, tok, "vm2", "infra", "alice", tb); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}

	resp1, err := http.Get(env.srv.URL + "/enroll/" + tok + "?user=alice")
	if err != nil {
		t.Fatalf("first GET: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp1.Body)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d, want 200", resp1.StatusCode)
	}

	resp2, err := http.Get(env.srv.URL + "/enroll/" + tok + "?user=alice")
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
	tb := env.seedUserTarball(t, "vmSC", "alice", []string{"infra"})
	env.seedPeerRow(t, "vmSC", "alice")
	if err := env.db.InsertToken(ctx, tok, "vmSC", "infra", "alice", tb); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}
	resp1, err := http.Get(env.srv.URL + "/enroll/" + tok + "?user=alice")
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
	env.seedPeerRow(t, "vmU", "alice")
	if err := env.db.InsertToken(ctx, tok, "vmU", "infra,databases", "alice", tb); err != nil {
		t.Fatalf("InsertToken: %v", err)
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
	wantNames := []string{
		"id_ed25519_" + testInstanceKey,
		"id_ed25519_" + testInstanceKey + "-cert.pub",
		"ca_authorized_keys",
		"known_hosts",
		"config",
	}
	if len(entries) != 5 {
		t.Errorf("user-mode tarball entries = %d, want 5: %v", len(entries), entries)
	}
	for _, n := range wantNames {
		if _, ok := entries[n]; !ok {
			t.Errorf("missing entry %q", n)
		}
	}
	// v2 must NOT ship a whole authorized_keys file (install appends the line).
	if _, ok := entries["authorized_keys"]; ok {
		t.Errorf("user-mode tarball must not ship a whole authorized_keys file")
	}
	for n := range entries {
		if strings.HasPrefix(n, "etc/") || strings.HasPrefix(n, "/") {
			t.Errorf("user-mode entry has root path %q", n)
		}
	}
	ak := string(entries["ca_authorized_keys"])
	if !strings.HasPrefix(ak, `cert-authority,principals="manager,infra,databases" `) {
		t.Errorf("ca_authorized_keys wrong: %q", ak)
	}
	peer, err := env.db.GetPeer(ctx, "vmU")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if peer.TargetUser != "alice" {
		t.Errorf("peer.TargetUser=%q, want alice", peer.TargetUser)
	}
}

func TestEnrollUserMode_NoPresetValidQuery(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	const tok = "tok-up-noprese"
	tb := env.seedUserTarball(t, "vmNP", "alice", []string{"infra"})
	env.seedPeerRow(t, "vmNP", "")
	if err := env.db.InsertToken(ctx, tok, "vmNP", "infra", "", tb); err != nil {
		t.Fatalf("InsertToken: %v", err)
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
	env.seedPeerRow(t, "vmNQ", "")
	if err := env.db.InsertToken(ctx, tok, "vmNQ", "infra", "", tb); err != nil {
		t.Fatalf("InsertToken: %v", err)
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
	env.seedPeerRow(t, "vmIQ", "")
	if err := env.db.InsertToken(ctx, tok, "vmIQ", "infra", "", tb); err != nil {
		t.Fatalf("InsertToken: %v", err)
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
	env.seedPeerRow(t, "vmM", "bob")
	if err := env.db.InsertToken(ctx, tok, "vmM", "infra", "bob", tb); err != nil {
		t.Fatalf("InsertToken: %v", err)
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
	env.seedPeerRow(t, "vmX", "bob")
	if err := env.db.InsertToken(ctx, tok, "vmX", "infra", "bob", tb); err != nil {
		t.Fatalf("InsertToken: %v", err)
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

// TestEnrollRootUser_TargetsHome verifies a --user root enrollment yields the
// same v2 user script that targets $HOME (so it works when run as root,
// installing into /root/.ssh) and records target_user=root.
func TestEnrollRootUser_TargetsHome(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	const tok = "tok-root-user"
	tb := env.seedUserTarball(t, "vmRoot", "root", []string{"infra"})
	env.seedPeerRow(t, "vmRoot", "root")
	if err := env.db.InsertToken(ctx, tok, "vmRoot", "infra", "root", tb); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}

	respScript, err := http.Get(env.srv.URL + "/enroll/" + tok + ".sh")
	if err != nil {
		t.Fatalf("GET .sh: %v", err)
	}
	defer respScript.Body.Close()
	if respScript.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(respScript.Body)
		t.Fatalf("script status = %d; body=%s", respScript.StatusCode, b)
	}
	s := string(mustRead(t, respScript.Body))
	for _, m := range []string{
		`TARGET_USER="$(id -un)"`,
		`USER_HOME="$HOME"`,
		`mkdir -p "$USER_HOME/.ssh"`,
		`curl -kfsSL ` + env.srv.URL + `/enroll/` + tok + `?user=$TARGET_USER | tar -xzC "$STAGE"`,
	} {
		if !strings.Contains(s, m) {
			t.Errorf("root-user script missing %q\nfull:\n%s", m, s)
		}
	}
	for _, forbidden := range []string{"systemctl reload sshd", "/etc/ssh/sshd_config", "/etc/ssh/ssh_config", "USER_HOME=/root"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("root-user script must NOT contain %q\nfull:\n%s", forbidden, s)
		}
	}

	resp, err := http.Get(env.srv.URL + "/enroll/" + tok + "?user=root")
	if err != nil {
		t.Fatalf("GET tarball: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("tarball status = %d, want 200 (?user=root must be accepted); body=%s", resp.StatusCode, b)
	}
	peer, err := env.db.GetPeer(ctx, "vmRoot")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if peer.TargetUser != "root" {
		t.Errorf("peer.TargetUser = %q, want root", peer.TargetUser)
	}
}

func TestEnrollNullTarball500(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	const tok = "tok-null-tarball"
	// Pre-upgrade token: a row with no stored tarball (NULL blob).
	env.seedPeerRow(t, "vmNull", "alice")
	if err := env.db.InsertToken(ctx, tok, "vmNull", "infra", "alice", nil); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}
	resp, err := http.Get(env.srv.URL + "/enroll/" + tok + "?user=alice")
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

// TestEnrollV2User_Script asserts the install script for any token is the v2
// user-mode script: it targets $HOME via id -un, appends the cert-authority
// line guarded by a grep, splices the keyed ~/.ssh/config block, and carries
// NONE of the host-level certhold directives and NO sshd reload.
func TestEnrollV2User_Script(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	const tok = "tok-v2-user"
	env.seedPeerRow(t, "vmV2U", "alice")
	if err := env.db.InsertToken(ctx, tok, "vmV2U", "infra", "alice", []byte("tb")); err != nil {
		t.Fatalf("InsertToken: %v", err)
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
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-shellscript; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	s := string(mustRead(t, resp.Body))

	mustContain := []string{
		"#!/usr/bin/env bash",
		"set -e",
		`TARGET_USER="$(id -un)"`,
		`USER_HOME="$HOME"`,
		`mkdir -p "$USER_HOME/.ssh"`,
		`chmod 700 "$USER_HOME/.ssh"`,
		`curl -kfsSL ` + env.srv.URL + `/enroll/` + tok + `?user=$TARGET_USER | tar -xzC "$STAGE"`,
		`install -m 600 "$STAGE/id_ed25519_` + testInstanceKey + `" "$USER_HOME/.ssh/id_ed25519_` + testInstanceKey + `"`,
		// grep-guarded idempotent authorized_keys append.
		`CA_KEY="$(awk '{print $3}' "$STAGE/ca_authorized_keys")"`,
		`if ! grep -qF "$CA_KEY" "$USER_HOME/.ssh/authorized_keys"; then cat "$STAGE/ca_authorized_keys" >> "$USER_HOME/.ssh/authorized_keys"; fi`,
		// keyed, version-agnostic sed splice of ~/.ssh/config.
		`sed -i -E "/^# BEGIN certhold ` + testInstanceKey + `( v[0-9]+)?\$/,/^# END certhold ` + testInstanceKey + `( v[0-9]+)?\$/d" "$USER_HOME/.ssh/config"`,
		"# BEGIN certhold " + testInstanceKey + " v2",
		"# END certhold " + testInstanceKey + " v2",
		// Feature 3 peer-side passphrase block.
		`if [ "${CERTHOLD_NO_PASSPHRASE:-}" != "1" ]; then`,
		`ssh-keygen -p -f "$KEY"`,
		// T02: per-file status lines and final success block.
		`Changed files:`,
		`  + ~/.ssh/id_ed25519_` + testInstanceKey + `            (installed, 0600 - private key)`,
		`  + ~/.ssh/id_ed25519_` + testInstanceKey + `-cert.pub   (installed, 0644 - certificate)`,
		`  ~ ~/.ssh/known_hosts                       (appended manager host key)`,
		`  ~ ~/.ssh/authorized_keys                   (appended cert-authority line)`,
		`  ~ ~/.ssh/config                            (replaced certhold block)`,
		`Success`,
		`ssh $TARGET_USER@`,
	}
	for _, m := range mustContain {
		if !strings.Contains(s, m) {
			t.Errorf("v2 user script missing %q\nfull:\n%s", m, s)
		}
	}

	// T02: the Success block must come AFTER the file ops (install -m 644 is the
	// last unconditional install step).
	if iSuccess, iInstall := strings.Index(s, "Success"), strings.Index(s, "install -m 644"); iSuccess <= iInstall {
		t.Errorf("Success line must appear AFTER install -m 644 (Success@%d, install@%d)\nfull:\n%s", iSuccess, iInstall, s)
	}
	// The v2 user script must NOT carry any host-level certhold directives,
	// touch the global sshd/ssh configs, or reload sshd.
	for _, forbidden := range []string{
		"TrustedUserCAKeys",
		"AuthorizedPrincipalsFile",
		"RevokedKeys",
		"HostCertificate",
		"auth_principals",
		"/etc/ssh/peer_ed25519",
		"systemctl reload sshd",
		"/etc/ssh/sshd_config",
		"/etc/ssh/ssh_config",
		"USER_HOME=/root",
	} {
		if strings.Contains(s, forbidden) {
			t.Errorf("v2 user script must NOT contain %q\nfull:\n%s", forbidden, s)
		}
	}
}

func mustRead(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return b
}

// TestEnrollV2Script_BashSyntax syntax-checks the rendered install script with
// `bash -n` so a broken echo/quote regression fails CI even if no peer runs it.
func TestEnrollV2Script_BashSyntax(t *testing.T) {
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skipf("bash not on PATH (%v); skipping syntax check", err)
	}

	script := v2Script("https://demo.example", "TOKEN123", testInstanceKey)
	tmpFile := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(tmpFile, []byte(script), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
	cmd := exec.Command(bashPath, "-n", tmpFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash -n failed: %v\nstderr+stdout:\n%s\nscript:\n%s", err, out, script)
	}
}

// TestEnrollV2Script_ExecutionSmoke runs the install script against a HOME
// tempdir, substituting a pre-built tarball for the curl/tar pipe. It asserts
// status lines + the Success line appear on stdout, and that the
// authorized_keys "appended" line is NOT printed on a second run (idempotency).
func TestEnrollV2Script_ExecutionSmoke(t *testing.T) {
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skipf("bash not on PATH (%v); skipping execution smoke", err)
	}

	const baseURL = "https://demo.example"
	const tok = "TOKEN123"
	script := v2Script(baseURL, tok, testInstanceKey)
	keyFile := peerfiles.V2KeyFileName(testInstanceKey)

	tarDir := t.TempDir()
	fixturePath := filepath.Join(tarDir, "peer.tgz")
	{
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		entries := []struct {
			name string
			body []byte
		}{
			{keyFile, []byte("FAKE_PRIVKEY\n")},
			{keyFile + "-cert.pub", []byte("ssh-ed25519-cert-v01@openssh.com FAKECERT keyid\n")},
			{"known_hosts", []byte("manager.example ssh-ed25519 FAKEHOSTKEY\n")},
			{"ca_authorized_keys", []byte(`cert-authority,principals="manager" ssh-ed25519 FAKECAKEY ca-comment` + "\n")},
		}
		for _, e := range entries {
			if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body))}); err != nil {
				t.Fatalf("tar header %s: %v", e.name, err)
			}
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("tar write %s: %v", e.name, err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatalf("tar close: %v", err)
		}
		if err := gz.Close(); err != nil {
			t.Fatalf("gz close: %v", err)
		}
		if err := os.WriteFile(fixturePath, buf.Bytes(), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}

	curlLine := `curl -kfsSL ` + baseURL + `/enroll/` + tok + `?user=$TARGET_USER | tar -xzC "$STAGE"`
	replacement := `tar -xzf ` + fixturePath + ` -C "$STAGE"`
	if !strings.Contains(script, curlLine) {
		t.Fatalf("script missing curl line %q\nscript:\n%s", curlLine, script)
	}
	patched := strings.Replace(script, curlLine, replacement, 1)

	home := t.TempDir()
	scriptPath := filepath.Join(home, "install.sh")
	if err := os.WriteFile(scriptPath, []byte(patched), 0o700); err != nil {
		t.Fatalf("write patched script: %v", err)
	}

	runScript := func() (string, string, error) {
		cmd := exec.Command(bashPath, scriptPath)
		cmd.Env = append(os.Environ(),
			"HOME="+home,
			"CERTHOLD_NO_PASSPHRASE=1",
		)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}

	stdout1, stderr1, err := runScript()
	if err != nil {
		t.Fatalf("first run failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout1, stderr1)
	}
	mustContainStdout := []string{
		"Changed files:",
		"~/.ssh/" + keyFile,
		"~/.ssh/" + keyFile + "-cert.pub",
		"~/.ssh/known_hosts",
		"~/.ssh/authorized_keys",
		"~/.ssh/config",
		"Success",
		"ssh ",
	}
	for _, m := range mustContainStdout {
		if !strings.Contains(stdout1, m) {
			t.Errorf("first run stdout missing %q\nstdout:\n%s", m, stdout1)
		}
	}

	stdout2, stderr2, err := runScript()
	if err != nil {
		t.Fatalf("second run failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout2, stderr2)
	}
	if strings.Contains(stdout2, "appended cert-authority line") {
		t.Errorf("second run printed authorized_keys appended line (idempotency broken)\nstdout:\n%s", stdout2)
	}
	if !strings.Contains(stdout2, "Success") {
		t.Errorf("second run stdout missing Success block\nstdout:\n%s", stdout2)
	}
}
