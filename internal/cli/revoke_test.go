package cli

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/sshpush"
)

type revokeMockPusher struct {
	host string
	rec  *pushRecord
}

type pushRecord struct {
	mu       sync.Mutex
	calls    []revokeMockCall
	failOn   map[string]error
	readData map[string][]byte
}

type revokeMockCall struct {
	host    string
	path    string
	content []byte
	mode    fs.FileMode
}

func (r *pushRecord) calls_() []revokeMockCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]revokeMockCall, len(r.calls))
	copy(out, r.calls)
	return out
}

func (m *revokeMockPusher) WriteFileAtomic(ctx context.Context, p string, content []byte, mode fs.FileMode) error {
	m.rec.mu.Lock()
	defer m.rec.mu.Unlock()
	if err, ok := m.rec.failOn[m.host]; ok {
		return err
	}
	m.rec.calls = append(m.rec.calls, revokeMockCall{host: m.host, path: p, content: content, mode: mode})
	return nil
}
func (m *revokeMockPusher) ReadFile(ctx context.Context, p string) ([]byte, error) {
	m.rec.mu.Lock()
	defer m.rec.mu.Unlock()
	if m.rec.readData != nil {
		if data, ok := m.rec.readData[m.host+":"+p]; ok {
			return append([]byte(nil), data...), nil
		}
	}
	return nil, nil
}
func (m *revokeMockPusher) ReloadSSHD(ctx context.Context) error   { return nil }
func (m *revokeMockPusher) VerifyHealth(ctx context.Context) error { return nil }
func (m *revokeMockPusher) Close() error                           { return nil }

// setupRevokeEnv prepares a data-dir + db with a CA, three peers, and
// installs the package-level injection points. Returns dataDir, dbPath,
// the push record, and a cleanup to restore globals.
func setupRevokeEnv(t *testing.T, dialErrs map[string]error) (string, string, *pushRecord, func()) {
	t.Helper()
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	dbPath := filepath.Join(dir, "state.db")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	if _, err := ca.Generate(filepath.Join(dataDir, "ca")); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	ctx := context.Background()
	for i, name := range []string{"alpha", "beta", "gamma"} {
		if err := d.InsertPeer(ctx, name, uint64(100+i), "fp-"+name, []byte("key-"+name)); err != nil {
			t.Fatalf("InsertPeer %s: %v", name, err)
		}
	}

	rec := &pushRecord{failOn: dialErrs}
	if rec.failOn == nil {
		rec.failOn = map[string]error{}
	}

	origBuild := buildKRLFn
	origDial := revokeDial
	buildKRLFn = func(ctx context.Context, caPub string, serials []uint64) ([]byte, error) {
		return []byte("FAKEKRL"), nil
	}
	revokeDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		rec.mu.Lock()
		err, ok := rec.failOn["dial:"+host]
		rec.mu.Unlock()
		if ok {
			return nil, err
		}
		return &revokeMockPusher{host: host, rec: rec}, nil
	}
	cleanup := func() {
		buildKRLFn = origBuild
		revokeDial = origDial
	}
	return dataDir, dbPath, rec, cleanup
}

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

func TestRevokeFlipsAndPushes(t *testing.T) {
	dataDir, dbPath, rec, cleanup := setupRevokeEnv(t, nil)
	defer cleanup()

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := d.SetPeerRevoked(context.Background(), "beta"); err != nil {
		t.Fatalf("SetPeerRevoked beta: %v", err)
	}
	d.Close()

	stdout, stderr, err := runRevokeCmd(t, dataDir, dbPath, "gamma")
	if err != nil {
		t.Fatalf("revoke: err=%v stderr=%s", err, stderr)
	}

	d2, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d2.Close()
	g, err := d2.GetPeer(context.Background(), "gamma")
	if err != nil {
		t.Fatalf("GetPeer gamma: %v", err)
	}
	if !g.Revoked {
		t.Errorf("gamma not revoked")
	}

	calls := rec.calls_()
	if len(calls) != 1 {
		t.Fatalf("expected 1 push call, got %d: %+v", len(calls), calls)
	}
	if calls[0].host != "alpha" {
		t.Errorf("push host = %q, want alpha", calls[0].host)
	}
	if calls[0].path != "/etc/ssh/krl" {
		t.Errorf("push path = %q, want /etc/ssh/krl", calls[0].path)
	}
	if string(calls[0].content) != "FAKEKRL" {
		t.Errorf("push content = %q, want FAKEKRL", calls[0].content)
	}

	a, err := d2.GetPeer(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("GetPeer alpha: %v", err)
	}
	if a.LastKRLVersion != 1 {
		t.Errorf("alpha LastKRLVersion = %d, want 1", a.LastKRLVersion)
	}

	b, err := d2.GetPeer(context.Background(), "beta")
	if err != nil {
		t.Fatalf("GetPeer beta: %v", err)
	}
	if b.LastKRLVersion != 0 {
		t.Errorf("beta LastKRLVersion = %d, want 0 (revoked, not pushed)", b.LastKRLVersion)
	}

	if stdout == "" {
		t.Errorf("expected summary output, got empty")
	}
}

// TestRevokeFanOutDialsDialHost verifies the v1-root KRL fan-out dials each
// other peer's DialHost() (address when set, name otherwise) while still logging
// and recording KRL state by name.
func TestRevokeFanOutDialsDialHost(t *testing.T) {
	dataDir, dbPath, rec, cleanup := setupRevokeEnv(t, nil)
	defer cleanup()

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	// alpha gets an address; beta stays name-only. gamma is the revoked peer.
	if err := d.SetPeerAddress(context.Background(), "alpha", "10.0.0.1"); err != nil {
		t.Fatalf("SetPeerAddress alpha: %v", err)
	}
	d.Close()

	stdout, stderr, err := runRevokeCmd(t, dataDir, dbPath, "gamma")
	if err != nil {
		t.Fatalf("revoke: err=%v stderr=%s stdout=%s", err, stderr, stdout)
	}

	dialed := map[string]bool{}
	for _, c := range rec.calls_() {
		dialed[c.host] = true
	}
	if !dialed["10.0.0.1"] {
		t.Errorf("expected fan-out to dial alpha's address 10.0.0.1; dialed=%v", dialed)
	}
	if !dialed["beta"] {
		t.Errorf("expected fan-out to dial beta by name (no address); dialed=%v", dialed)
	}
	if dialed["alpha"] {
		t.Errorf("alpha should be dialed by address, not name; dialed=%v", dialed)
	}

	// last_krl_version is still keyed by name, not address.
	d2, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d2.Close()
	a, err := d2.GetPeer(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("GetPeer alpha: %v", err)
	}
	if a.LastKRLVersion != 1 {
		t.Errorf("alpha LastKRLVersion = %d, want 1", a.LastKRLVersion)
	}
}

func TestRevokeUnknownPeer(t *testing.T) {
	dataDir, dbPath, rec, cleanup := setupRevokeEnv(t, nil)
	defer cleanup()

	_, _, err := runRevokeCmd(t, dataDir, dbPath, "nosuch")
	if err == nil {
		t.Fatal("expected error for unknown peer")
	}
	if len(rec.calls_()) != 0 {
		t.Errorf("no pushes expected for unknown peer, got %d", len(rec.calls_()))
	}
}

// TestRevokeUserModeTriggersRekey verifies that revoking a user-mode peer
// goes through the rekey path (rotates the CA) rather than pushing a KRL.
func TestRevokeUserModeTriggersRekey(t *testing.T) {
	t.Setenv("CERTHOLD_CA_PASSPHRASE", "test-ca-pw")
	t.Setenv("CERTHOLD_PEER_PASSPHRASE", "test-peer-pw")
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	dbPath := filepath.Join(dir, "state.db")
	hostname := "mgr"

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// init with root mode for the manager so the self files path resolves
	// deterministically for the test.
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", hostname, "--mode", "root"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("init: %v\n%s", err, buf.String())
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	// Insert two user-mode peers.
	for _, name := range []string{"alpha", "beta"} {
		_, pubAuth, sshPub, err := ca.GeneratePeerKey()
		if err != nil {
			t.Fatalf("GeneratePeerKey %s: %v", name, err)
		}
		_ = sshPub
		if err := d.InsertPeerWithMode(ctx, name, 100, "fp-"+name, pubAuth, db.ModeUser, "root", 1); err != nil {
			t.Fatalf("InsertPeerWithMode %s: %v", name, err)
		}
		if err := d.EnsureGroup(ctx, "infra"); err != nil {
			t.Fatalf("EnsureGroup: %v", err)
		}
		if err := d.SetPeerGroups(ctx, name, []string{"infra"}); err != nil {
			t.Fatalf("SetPeerGroups: %v", err)
		}
		if err := d.SetPeerAllowedGroups(ctx, name, []string{"infra"}); err != nil {
			t.Fatalf("SetPeerAllowedGroups: %v", err)
		}
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
	cmd2.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "revoke", "alpha", "--hostname", hostname})
	if err := cmd2.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("revoke: err=%v stderr=%s stdout=%s", err, errBuf.String(), out.String())
	}

	calls := rec.snapshot()
	sawBetaWriteAK := false
	sawBetaWriteCert := false
	sawAlphaPush := false
	sawKRL := false
	for _, c := range calls {
		if c.host == "alpha" && c.op == "write" {
			sawAlphaPush = true
		}
		if c.host == "beta" && c.op == "write" && c.path == "/root/.ssh/authorized_keys" {
			sawBetaWriteAK = true
		}
		if c.host == "beta" && c.op == "write" && c.path == "/root/.ssh/id_ed25519-cert.pub" {
			sawBetaWriteCert = true
		}
		if c.path == "/etc/ssh/krl" {
			sawKRL = true
		}
	}
	if sawAlphaPush {
		t.Errorf("revoked peer alpha should not be pushed to")
	}
	if !sawBetaWriteAK {
		t.Errorf("beta authorized_keys should be rewritten during user-mode revoke")
	}
	if !sawBetaWriteCert {
		t.Errorf("beta cert should be pushed during user-mode revoke")
	}
	if sawKRL {
		t.Errorf("user-mode revoke must not push KRL")
	}

	d2, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d2.Close()
	a, err := d2.GetPeer(ctx, "alpha")
	if err != nil {
		t.Fatalf("GetPeer alpha: %v", err)
	}
	if !a.Revoked {
		t.Errorf("alpha not marked revoked")
	}
}

// TestRevokeV2Root_TriggersRekey_NoKRL verifies a v2 root peer revoke takes the
// partial-CA-rekey path (rewrites a non-revoked v2 peer's authorized_keys + cert)
// and never pushes a KRL.
func TestRevokeV2Root_TriggersRekey_NoKRL(t *testing.T) {
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
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", hostname, "--mode", "root"})
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
		if err := d.InsertPeerWithMode(ctx, name, 100, "fp-"+name, pubAuth, db.ModeRoot, "", 2); err != nil {
			t.Fatalf("InsertPeerWithMode %s: %v", name, err)
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
	cmd2.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "revoke", "alpha", "--hostname", hostname})
	if err := cmd2.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("revoke: err=%v stderr=%s stdout=%s", err, errBuf.String(), out.String())
	}

	sawBetaAK := false
	sawBetaCert := false
	sawKRL := false
	sawAlphaPush := false
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
		if c.path == "/etc/ssh/krl" {
			sawKRL = true
		}
	}
	if sawAlphaPush {
		t.Errorf("revoked peer alpha must not be pushed to")
	}
	if !sawBetaAK {
		t.Errorf("beta v2 authorized_keys should be rewritten on v2-root revoke")
	}
	if !sawBetaCert {
		t.Errorf("beta v2 namespaced cert should be pushed on v2-root revoke")
	}
	if sawKRL {
		t.Errorf("v2-root revoke must NOT push a KRL")
	}
}

// TestRevokeV2_StragglerStillCompletes verifies the revoke->runRekeyCore path
// inherits T04 resilience: revoking a v2 peer while another peer is unreachable
// still completes the CA rekey for the reachable peers, returns nil, and reports
// the straggler the same way `rekey` does.
func TestRevokeV2_StragglerStillCompletes(t *testing.T) {
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
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", hostname, "--mode", "root"})
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
		if err := d.InsertPeerWithMode(ctx, name, 100, "fp-"+name, pubAuth, db.ModeRoot, "", 2); err != nil {
			t.Fatalf("InsertPeerWithMode %s: %v", name, err)
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
	cmd2.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "revoke", "alpha", "--hostname", hostname})
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
	if ver, err := d2.ActiveCAVersion(ctx); err != nil || ver != 1 {
		t.Errorf("active ca version = %d (err=%v), want 1; CA swap must complete on revoke straggler", ver, err)
	}
	beta, _ := d2.GetPeer(ctx, "beta")
	if beta.Serial != prevBeta.Serial {
		t.Errorf("straggler beta cert_serial bumped (%d -> %d) despite unreachable push", prevBeta.Serial, beta.Serial)
	}
	gamma, _ := d2.GetPeer(ctx, "gamma")
	if gamma.Serial == prevGamma.Serial {
		t.Error("reachable gamma should have been rotated during revoke")
	}
	a, _ := d2.GetPeer(ctx, "alpha")
	if !a.Revoked {
		t.Error("alpha not marked revoked")
	}
}

func TestRevokePushFailureContinues(t *testing.T) {
	dataDir, dbPath, rec, cleanup := setupRevokeEnv(t, map[string]error{
		"dial:alpha": errors.New("boom"),
	})
	defer cleanup()

	d0, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := d0.SetPeerRevoked(context.Background(), "beta"); err != nil {
		t.Fatalf("SetPeerRevoked beta: %v", err)
	}
	d0.Close()

	stdout, stderr, err := runRevokeCmd(t, dataDir, dbPath, "gamma")
	if err != nil {
		t.Fatalf("revoke: err=%v stderr=%s", err, stderr)
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d.Close()
	a, err := d.GetPeer(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("GetPeer alpha: %v", err)
	}
	if a.LastKRLVersion != 0 {
		t.Errorf("alpha LastKRLVersion = %d, want 0 (push failed)", a.LastKRLVersion)
	}
	if len(rec.calls_()) != 0 {
		t.Errorf("expected 0 successful pushes, got %d", len(rec.calls_()))
	}
	if stdout == "" {
		t.Errorf("expected summary output even on partial failure")
	}
}
