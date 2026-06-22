package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/sshpush"
)

func runRevokeCmd(t *testing.T, dataDir, dbPath string, args ...string) (string, string, error) {
	t.Helper()
	cmd := NewRootCmd()
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	full := append([]string{"--data-dir", dataDir, "--db", dbPath, "revoke"}, args...)
	cmd.SetArgs(full)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), errBuf.String(), err
}

func TestRevokeUnknownPeer(t *testing.T) {
	t.Setenv("CERTHOLD_CA_PASSPHRASE", "test-ca-pw")
	t.Setenv("CERTHOLD_PEER_PASSPHRASE", "test-peer-pw")
	dataDir, dbPath, _, _, cleanup := setupRekeyEnv(t, nil)
	defer cleanup()

	if _, _, err := runRevokeCmd(t, dataDir, dbPath, "nosuch"); err == nil {
		t.Fatal("expected error for unknown peer")
	}
}

// TestRevokeRekeyTriggersRekey_NoKRL verifies that `revoke --rekey` goes through
// the partial-CA-rekey path (rotates the CA, rewrites a non-revoked peer's
// authorized_keys + cert), never pushes a KRL, and ends with the revoked row
// deleted.
func TestRevokeRekeyTriggersRekey_NoKRL(t *testing.T) {
	t.Setenv("CERTHOLD_CA_PASSPHRASE", "test-ca-pw")
	t.Setenv("CERTHOLD_PEER_PASSPHRASE", "test-peer-pw")
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	dbPath := filepath.Join(dir, "state.db")
	hostname := "mgr"

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", hostname, "--user", "root"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("init: %v\n%s", err, buf.String())
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	key, _, _ := d.GetMeta(ctx, db.MetaInstanceKey)
	for _, name := range []string{"alpha", "beta"} {
		_, pubAuth, _, _ := ca.GeneratePeerKey()
		if err := d.InsertPeer(ctx, name, 100, "fp-"+name, pubAuth, "root", true, ""); err != nil {
			t.Fatalf("InsertPeer %s: %v", name, err)
		}
		_ = d.EnsureGroup(ctx, "infra")
		_ = d.SetPeerGroups(ctx, name, []string{"infra"})
		_ = d.SetPeerAllowedGroups(ctx, name, []string{"infra"})
	}
	d.Close()

	rec := &rekeyRecorder{}
	origRekeyDial := rekeyDial
	rekeyDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		return &rekeyMockPusher{host: host, rec: rec}, nil
	}
	defer func() { rekeyDial = origRekeyDial }()

	cmd2 := NewRootCmd()
	var out, errBuf bytes.Buffer
	cmd2.SetOut(&out)
	cmd2.SetErr(&errBuf)
	cmd2.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "revoke", "--rekey", "alpha", "--hostname", hostname})
	if err := cmd2.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("revoke: err=%v stderr=%s stdout=%s", err, errBuf.String(), out.String())
	}

	sawBetaAK := false
	sawBetaCert := false
	sawAlphaPush := false
	sawKRL := false
	for _, c := range rec.snapshot() {
		if c.host == "alpha" && c.op == "write" {
			sawAlphaPush = true
		}
		if c.host == "beta" && c.op == "write" && c.path == "/root/.ssh/authorized_keys" {
			sawBetaAK = true
		}
		if c.host == "beta" && c.op == "write" && c.path == "/root/.ssh/id_ed25519_"+key+"-cert.pub" {
			sawBetaCert = true
		}
		if strings.Contains(c.path, "krl") {
			sawKRL = true
		}
	}
	if sawAlphaPush {
		t.Errorf("revoked peer alpha should not be pushed to")
	}
	if !sawBetaAK {
		t.Errorf("beta authorized_keys should be rewritten during revoke")
	}
	if !sawBetaCert {
		t.Errorf("beta cert should be pushed during revoke")
	}
	if sawKRL {
		t.Errorf("revoke must not push a KRL")
	}

	d2, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d2.Close()
	if _, err := d2.GetPeer(ctx, "alpha"); !errors.Is(err, db.ErrPeerNotFound) {
		t.Errorf("alpha row should be deleted after --rekey revoke, got err=%v", err)
	}
}

// TestRevokeStragglerStillCompletes verifies the revoke --rekey path
// inherits T04 resilience: revoking a peer while another peer is unreachable
// still completes the CA rekey for the reachable peers, returns nil, and reports
// the straggler the same way `rekey` does.
func TestRevokeStragglerStillCompletes(t *testing.T) {
	t.Setenv("CERTHOLD_CA_PASSPHRASE", "test-ca-pw")
	t.Setenv("CERTHOLD_PEER_PASSPHRASE", "test-peer-pw")
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	dbPath := filepath.Join(dir, "state.db")
	hostname := "mgr"
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", hostname, "--user", "root"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("init: %v\n%s", err, buf.String())
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	// alpha is revoked; beta is the unreachable straggler; gamma is reachable.
	for _, name := range []string{"alpha", "beta", "gamma"} {
		_, pubAuth, _, _ := ca.GeneratePeerKey()
		if err := d.InsertPeer(ctx, name, 100, "fp-"+name, pubAuth, "root", true, ""); err != nil {
			t.Fatalf("InsertPeer %s: %v", name, err)
		}
		_ = d.EnsureGroup(ctx, "infra")
		_ = d.SetPeerGroups(ctx, name, []string{"infra"})
		_ = d.SetPeerAllowedGroups(ctx, name, []string{"infra"})
	}
	prevBeta, _ := d.GetPeer(ctx, "beta")
	prevGamma, _ := d.GetPeer(ctx, "gamma")
	d.Close()

	rec := &rekeyRecorder{failOn: map[string]error{"dial:beta": errors.New("connection refused")}}
	origRekeyDial := rekeyDial
	rekeyDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		rec.mu.Lock()
		e, ok := rec.failOn["dial:"+host]
		rec.mu.Unlock()
		if ok {
			return nil, e
		}
		return &rekeyMockPusher{host: host, rec: rec}, nil
	}
	defer func() { rekeyDial = origRekeyDial }()

	cmd2 := NewRootCmd()
	var out, errBuf bytes.Buffer
	cmd2.SetOut(&out)
	cmd2.SetErr(&errBuf)
	cmd2.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "revoke", "--rekey", "alpha", "--hostname", hostname})
	if err := cmd2.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("revoke must return nil with one straggler; got err=%v stderr=%s stdout=%s", err, errBuf.String(), out.String())
	}

	stderr := errBuf.String()
	if !strings.Contains(stderr, "beta") || !strings.Contains(stderr, "STILL TRUST THE PREVIOUS CA") {
		t.Errorf("expected straggler warning naming beta in revoke stderr, got: %s", stderr)
	}

	d2, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d2.Close()
	if ver, err := d2.ActiveCAVersion(ctx); err != nil || ver != 2 {
		t.Errorf("active ca version = %d (err=%v), want 2; CA swap must complete on revoke straggler", ver, err)
	}
	beta, _ := d2.GetPeer(ctx, "beta")
	if beta.Serial != prevBeta.Serial {
		t.Errorf("straggler beta cert_serial bumped (%d -> %d) despite unreachable push", prevBeta.Serial, beta.Serial)
	}
	gamma, _ := d2.GetPeer(ctx, "gamma")
	if gamma.Serial == prevGamma.Serial {
		t.Error("reachable gamma should have been rotated during revoke")
	}
	if _, err := d2.GetPeer(ctx, "alpha"); !errors.Is(err, db.ErrPeerNotFound) {
		t.Errorf("alpha row should be deleted after --rekey revoke, got err=%v", err)
	}
}

// TestRevokeDefaultClearsAndDeletes verifies the default (no --rekey) path:
// certhold clears the reachable inbound peer over SSH and deletes its row,
// without rotating the CA.
func TestRevokeDefaultClearsAndDeletes(t *testing.T) {
	t.Setenv("CERTHOLD_CA_PASSPHRASE", "test-ca-pw")
	t.Setenv("CERTHOLD_PEER_PASSPHRASE", "test-peer-pw")
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	dbPath := filepath.Join(dir, "state.db")
	hostname := "mgr"
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", hostname, "--user", "root"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("init: %v\n%s", err, buf.String())
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	for _, name := range []string{"alpha", "beta"} {
		_, pubAuth, _, _ := ca.GeneratePeerKey()
		if err := d.InsertPeer(ctx, name, 100, "fp-"+name, pubAuth, "root", true, ""); err != nil {
			t.Fatalf("InsertPeer %s: %v", name, err)
		}
		_ = d.EnsureGroup(ctx, "infra")
		_ = d.SetPeerGroups(ctx, name, []string{"infra"})
		_ = d.SetPeerAllowedGroups(ctx, name, []string{"infra"})
	}
	oldVer, _ := d.ActiveCAVersion(ctx)
	d.Close()

	rec := &rekeyRecorder{}
	origRekeyDial := rekeyDial
	rekeyDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		return &rekeyMockPusher{host: host, rec: rec}, nil
	}
	defer func() { rekeyDial = origRekeyDial }()

	cmd2 := NewRootCmd()
	var out, errBuf bytes.Buffer
	cmd2.SetOut(&out)
	cmd2.SetErr(&errBuf)
	cmd2.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "revoke", "alpha", "--hostname", hostname})
	if err := cmd2.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("revoke: err=%v stderr=%s stdout=%s", err, errBuf.String(), out.String())
	}

	sawAlphaClear := false
	for _, c := range rec.snapshot() {
		if c.host != "alpha" {
			t.Errorf("only alpha should be contacted on a default revoke, got %+v", c)
		}
		if c.op == "clear" {
			sawAlphaClear = true
		}
	}
	if !sawAlphaClear {
		t.Error("alpha should have been cleared on a default revoke")
	}

	d2, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d2.Close()
	if _, err := d2.GetPeer(ctx, "alpha"); !errors.Is(err, db.ErrPeerNotFound) {
		t.Errorf("alpha row should be deleted after default revoke, got err=%v", err)
	}
	if _, err := d2.GetPeer(ctx, "beta"); err != nil {
		t.Errorf("beta should be untouched by a default revoke: %v", err)
	}
	if newVer, err := d2.ActiveCAVersion(ctx); err != nil || newVer != oldVer {
		t.Errorf("default revoke must NOT rotate the CA: version %d -> %d (err=%v)", oldVer, newVer, err)
	}
}

// TestRevokeDefaultClientPeerErrors verifies the --rekey flag plumbing is
// independent of the default path: a client (no-inbound) peer revoked without
// --rekey errors and is preserved, never dialed.
func TestRevokeDefaultClientPeerErrors(t *testing.T) {
	t.Setenv("CERTHOLD_CA_PASSPHRASE", "test-ca-pw")
	t.Setenv("CERTHOLD_PEER_PASSPHRASE", "test-peer-pw")
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	dbPath := filepath.Join(dir, "state.db")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", "mgr", "--user", "root"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("init: %v\n%s", err, buf.String())
	}
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	_, pubAuth, _, _ := ca.GeneratePeerKey()
	if err := d.InsertPeer(ctx, "laptop", 1, "fp-laptop", pubAuth, "alice", false, "tok"); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	d.Close()

	dialed := false
	origRekeyDial := rekeyDial
	rekeyDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		dialed = true
		return &rekeyMockPusher{host: host, rec: &rekeyRecorder{}}, nil
	}
	defer func() { rekeyDial = origRekeyDial }()

	if _, _, err := runRevokeCmd(t, dataDir, dbPath, "laptop"); err == nil {
		t.Fatal("expected error revoking a client peer without --rekey")
	}
	if dialed {
		t.Error("client peer must not be dialed on a default revoke")
	}
	d2, _ := db.Open(dbPath)
	defer d2.Close()
	if _, err := d2.GetPeer(ctx, "laptop"); err != nil {
		t.Errorf("client peer row must be preserved: %v", err)
	}
}
