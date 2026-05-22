package cli

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/sshpush"
)

const (
	expectedSelfCertRel       = "self/etc/ssh/peer_ed25519-cert.pub"
	expectedSelfKeyRel        = "self/etc/ssh/peer_ed25519"
	expectedSelfKnownHostsRel = "self/etc/ssh/ca_known_hosts"
)

type fakePushCall struct {
	op      string
	path    string
	content []byte
	mode    fs.FileMode
}

type fakePusher struct {
	mu     sync.Mutex
	calls  []fakePushCall
	closed bool
	errOn  string
}

func (f *fakePusher) record(c fakePushCall) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
	if f.errOn != "" && f.errOn == c.op {
		return errors.New("fake error: " + c.op)
	}
	return nil
}

func (f *fakePusher) WriteFileAtomic(ctx context.Context, path string, content []byte, mode fs.FileMode) error {
	return f.record(fakePushCall{op: "write", path: path, content: content, mode: mode})
}

func (f *fakePusher) ReloadSSHD(ctx context.Context) error {
	return f.record(fakePushCall{op: "reload"})
}

func (f *fakePusher) VerifyHealth(ctx context.Context) error {
	return f.record(fakePushCall{op: "verify"})
}

func (f *fakePusher) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakePusher) Calls() []fakePushCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakePushCall, len(f.calls))
	copy(out, f.calls)
	return out
}

func installFakePusher(t *testing.T) *fakePusher {
	t.Helper()
	fp := &fakePusher{}
	prev := groupDial
	groupDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		return fp, nil
	}
	t.Cleanup(func() { groupDial = prev })
	return fp
}

func installFakePusherCapturingOpts(t *testing.T, capturedOpts *sshpush.Options) *fakePusher {
	t.Helper()
	fp := &fakePusher{}
	prev := groupDial
	groupDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		*capturedOpts = opts
		return fp, nil
	}
	t.Cleanup(func() { groupDial = prev })
	return fp
}

func seedGroupDB(t *testing.T, allowed []string) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	ctx := context.Background()
	if err := d.InsertPeer(ctx, "peer1", 1, "fp", []byte("k")); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	for _, g := range allowed {
		if err := d.EnsureGroup(ctx, g); err != nil {
			t.Fatalf("EnsureGroup %s: %v", g, err)
		}
	}
	if err := d.SetPeerAllowedGroups(ctx, "peer1", allowed); err != nil {
		t.Fatalf("SetPeerAllowedGroups: %v", err)
	}
	return dbPath
}

func runGroupCmd(t *testing.T, dbPath string, args ...string) (string, error) {
	t.Helper()
	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	full := append([]string{"--db", dbPath, "--data-dir", t.TempDir(), "group"}, args...)
	root.SetArgs(full)
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

func getAllowed(t *testing.T, dbPath string) []string {
	t.Helper()
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	got, err := d.GetPeerAllowedGroups(context.Background(), "peer1")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	return got
}

func TestGroupAllowAddsAndPushes(t *testing.T) {
	dbPath := seedGroupDB(t, []string{"a", "b"})
	fp := installFakePusher(t)

	out, err := runGroupCmd(t, dbPath, "allow", "c", "--on", "peer1")
	if err != nil {
		t.Fatalf("allow: err=%v out=%s", err, out)
	}

	got := getAllowed(t, dbPath)
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("allowed = %v, want %v", got, want)
	}

	calls := fp.Calls()
	if len(calls) != 3 {
		t.Fatalf("expected 3 calls (write, reload, verify), got %d: %+v", len(calls), calls)
	}
	if calls[0].op != "write" || calls[0].path != "/etc/ssh/auth_principals/root" {
		t.Errorf("call[0] = %+v, want write to /etc/ssh/auth_principals/root", calls[0])
	}
	if string(calls[0].content) != "manager\na\nb\nc\n" {
		t.Errorf("content = %q, want %q", string(calls[0].content), "manager\na\nb\nc\n")
	}
	if calls[0].mode != fs.FileMode(0644) {
		t.Errorf("mode = %o, want 0644", calls[0].mode)
	}
	if calls[1].op != "reload" {
		t.Errorf("call[1] op = %s, want reload", calls[1].op)
	}
	if calls[2].op != "verify" {
		t.Errorf("call[2] op = %s, want verify", calls[2].op)
	}
}

func TestGroupDisallowRemovesAndPushes(t *testing.T) {
	dbPath := seedGroupDB(t, []string{"a", "b", "c"})
	fp := installFakePusher(t)

	out, err := runGroupCmd(t, dbPath, "disallow", "a", "--on", "peer1")
	if err != nil {
		t.Fatalf("disallow: err=%v out=%s", err, out)
	}

	got := getAllowed(t, dbPath)
	want := []string{"b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("allowed = %v, want %v", got, want)
	}

	calls := fp.Calls()
	if len(calls) != 3 {
		t.Fatalf("expected 3 calls, got %d", len(calls))
	}
	if string(calls[0].content) != "manager\nb\nc\n" {
		t.Errorf("content = %q, want %q", string(calls[0].content), "manager\nb\nc\n")
	}
}

func TestGroupAllowIdempotent(t *testing.T) {
	dbPath := seedGroupDB(t, []string{"a", "b", "c"})
	fp := installFakePusher(t)

	out, err := runGroupCmd(t, dbPath, "allow", "c", "--on", "peer1")
	if err != nil {
		t.Fatalf("allow: err=%v out=%s", err, out)
	}

	got := getAllowed(t, dbPath)
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("allowed = %v, want %v", got, want)
	}
	if calls := fp.Calls(); len(calls) != 0 {
		t.Errorf("expected no push calls for idempotent allow, got %d: %+v", len(calls), calls)
	}
}

func TestGroupDisallowMissingIsNoop(t *testing.T) {
	dbPath := seedGroupDB(t, []string{"a", "b"})
	fp := installFakePusher(t)

	out, err := runGroupCmd(t, dbPath, "disallow", "z", "--on", "peer1")
	if err != nil {
		t.Fatalf("disallow: err=%v out=%s", err, out)
	}

	got := getAllowed(t, dbPath)
	want := []string{"a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("allowed = %v, want %v", got, want)
	}
	if calls := fp.Calls(); len(calls) != 0 {
		t.Errorf("expected no push calls, got %d", len(calls))
	}
}

func TestGroupContentAlwaysStartsWithManager(t *testing.T) {
	dbPath := seedGroupDB(t, nil)
	fp := installFakePusher(t)

	if _, err := runGroupCmd(t, dbPath, "allow", "x", "--on", "peer1"); err != nil {
		t.Fatalf("allow: %v", err)
	}
	calls := fp.Calls()
	if len(calls) == 0 {
		t.Fatal("no push calls")
	}
	if string(calls[0].content) != "manager\nx\n" {
		t.Errorf("content = %q, want %q", string(calls[0].content), "manager\nx\n")
	}
}

func TestGroupAllowMissingPeer(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	d.Close()
	installFakePusher(t)

	if _, err := runGroupCmd(t, dbPath, "allow", "g", "--on", "missing"); err == nil {
		t.Fatal("expected error for missing peer")
	}
}

func TestGroupSSHOptionsPathsMatchInitLayout(t *testing.T) {
	dbPath := seedGroupDB(t, nil)
	var captured sshpush.Options
	installFakePusherCapturingOpts(t, &captured)

	dataDir := t.TempDir()
	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "group", "allow", "g", "--on", "peer1"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("allow: err=%v out=%s", err, out.String())
	}

	wantCert := filepath.Join(dataDir, expectedSelfCertRel)
	wantKey := filepath.Join(dataDir, expectedSelfKeyRel)
	wantKH := filepath.Join(dataDir, expectedSelfKnownHostsRel)

	if captured.CertPath != wantCert {
		t.Errorf("CertPath = %q, want %q", captured.CertPath, wantCert)
	}
	if captured.KeyPath != wantKey {
		t.Errorf("KeyPath = %q, want %q", captured.KeyPath, wantKey)
	}
	if captured.KnownHostsPath != wantKH {
		t.Errorf("KnownHostsPath = %q, want %q", captured.KnownHostsPath, wantKH)
	}
}

func TestGroupAllowRequiresOnFlag(t *testing.T) {
	dbPath := seedGroupDB(t, nil)
	installFakePusher(t)
	if _, err := runGroupCmd(t, dbPath, "allow", "g"); err == nil {
		t.Fatal("expected error when --on is missing")
	}
}
