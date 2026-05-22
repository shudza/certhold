package cli

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
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
	mu     sync.Mutex
	calls  []revokeMockCall
	failOn map[string]error
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
func (m *revokeMockPusher) ReloadSSHD(ctx context.Context) error  { return nil }
func (m *revokeMockPusher) VerifyHealth(ctx context.Context) error { return nil }
func (m *revokeMockPusher) Close() error                            { return nil }

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
