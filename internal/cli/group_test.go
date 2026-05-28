package cli

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/shudza/certhold/internal/ca"
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
	mu       sync.Mutex
	calls    []fakePushCall
	closed   bool
	errOn    string
	readData map[string][]byte
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

func (f *fakePusher) ReadFile(ctx context.Context, path string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fakePushCall{op: "read", path: path})
	if f.errOn == "read" {
		return nil, errors.New("fake error: read")
	}
	if data, ok := f.readData[path]; ok {
		return append([]byte(nil), data...), nil
	}
	return nil, nil
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

func installFakePusherCapturingHost(t *testing.T, gotHost *string) *fakePusher {
	t.Helper()
	fp := &fakePusher{}
	prev := groupDial
	groupDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		*gotHost = host
		return fp, nil
	}
	t.Cleanup(func() { groupDial = prev })
	return fp
}

func TestGroupDialsAddressWhenNoHostFlag(t *testing.T) {
	dbPath := seedGroupDB(t, []string{"a"})
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := d.SetPeerAddress(context.Background(), "peer1", "10.0.0.9"); err != nil {
		t.Fatalf("SetPeerAddress: %v", err)
	}
	d.Close()

	var gotHost string
	installFakePusherCapturingHost(t, &gotHost)
	if out, err := runGroupCmd(t, dbPath, "allow", "c", "--on", "peer1"); err != nil {
		t.Fatalf("allow: err=%v out=%s", err, out)
	}
	if gotHost != "10.0.0.9" {
		t.Errorf("dialed host = %q, want 10.0.0.9 (the peer address)", gotHost)
	}
}

func TestGroupHostFlagBeatsAddress(t *testing.T) {
	dbPath := seedGroupDB(t, []string{"a"})
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := d.SetPeerAddress(context.Background(), "peer1", "10.0.0.9"); err != nil {
		t.Fatalf("SetPeerAddress: %v", err)
	}
	d.Close()

	var gotHost string
	installFakePusherCapturingHost(t, &gotHost)
	if out, err := runGroupCmd(t, dbPath, "allow", "c", "--on", "peer1", "--host", "explicit.host"); err != nil {
		t.Fatalf("allow: err=%v out=%s", err, out)
	}
	if gotHost != "explicit.host" {
		t.Errorf("dialed host = %q, want explicit.host (--host overrides address)", gotHost)
	}
}

func TestGroupDialsNameWhenNoAddress(t *testing.T) {
	dbPath := seedGroupDB(t, []string{"a"})
	var gotHost string
	installFakePusherCapturingHost(t, &gotHost)
	if out, err := runGroupCmd(t, dbPath, "allow", "c", "--on", "peer1"); err != nil {
		t.Fatalf("allow: err=%v out=%s", err, out)
	}
	if gotHost != "peer1" {
		t.Errorf("dialed host = %q, want peer1 (the name, no address set)", gotHost)
	}
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

func setupGroupUserModeDB(t *testing.T, peerName, targetUser string, allowed []string) (dataDir, dbPath string) {
	t.Helper()
	dataDir = t.TempDir()
	if _, err := ca.Generate(filepath.Join(dataDir, "ca")); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	dbPath = filepath.Join(dataDir, "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	if err := d.InsertPeerWithMode(context.Background(), peerName, 1, "fp", []byte("k"), db.ModeUser, targetUser, 1); err != nil {
		t.Fatalf("InsertPeerWithMode: %v", err)
	}
	for _, g := range allowed {
		if err := d.EnsureGroup(context.Background(), g); err != nil {
			t.Fatalf("EnsureGroup: %v", err)
		}
	}
	if err := d.SetPeerAllowedGroups(context.Background(), peerName, allowed); err != nil {
		t.Fatalf("SetPeerAllowedGroups: %v", err)
	}
	return dataDir, dbPath
}

func runGroupUserModeCmd(t *testing.T, dataDir, dbPath string, args ...string) (string, error) {
	t.Helper()
	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	full := append([]string{"--db", dbPath, "--data-dir", dataDir, "group"}, args...)
	root.SetArgs(full)
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

func TestGroupAllow_UserMode_RewritesAuthorizedKeys_NoReload(t *testing.T) {
	dataDir, dbPath := setupGroupUserModeDB(t, "vmU", "alice", []string{"infra"})

	// Build the existing remote authorized_keys against the CA at dataDir/ca.
	caObj, err := ca.Load(filepath.Join(dataDir, "ca"))
	if err != nil {
		t.Fatalf("ca.Load: %v", err)
	}
	caTrim := strings.TrimRight(string(caObj.PublicKeyAuthorizedKey()), "\n")
	existing := []byte(`cert-authority,principals="manager,infra" ` + caTrim + "\n")

	fp := &fakePusher{readData: map[string][]byte{
		"/home/alice/.ssh/authorized_keys": existing,
	}}
	prev := groupDial
	groupDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		return fp, nil
	}
	t.Cleanup(func() { groupDial = prev })

	out, err := runGroupUserModeCmd(t, dataDir, dbPath, "allow", "db", "--on", "vmU")
	if err != nil {
		t.Fatalf("allow: err=%v out=%s", err, out)
	}

	calls := fp.Calls()
	// Expect read, write, verify — NO reload.
	var ops []string
	for _, c := range calls {
		ops = append(ops, c.op)
	}
	wantOps := []string{"read", "write", "verify"}
	if !reflect.DeepEqual(ops, wantOps) {
		t.Errorf("ops = %v, want %v (calls=%+v)", ops, wantOps, calls)
	}
	var writeCall *fakePushCall
	for i := range calls {
		if calls[i].op == "write" {
			writeCall = &calls[i]
			break
		}
	}
	if writeCall == nil {
		t.Fatal("no write call")
	}
	if writeCall.path != "/home/alice/.ssh/authorized_keys" {
		t.Errorf("write path = %q, want /home/alice/.ssh/authorized_keys", writeCall.path)
	}
	wantLine := `cert-authority,principals="manager,infra,db" ` + caTrim
	if !strings.Contains(string(writeCall.content), wantLine) {
		t.Errorf("write content does not contain %q\ncontent:\n%s", wantLine, writeCall.content)
	}
}

// TestGroupAllow_UserMode_EncryptedCA_NoCAPassphrase asserts that group only
// reads the CA public key: with an encrypted CA on disk and CERTHOLD_CA_PASSPHRASE
// deliberately unset, the command still succeeds (it never prompts for the CA
// passphrase — only the peer passphrase, which the mock dialer never exercises).
func TestGroupAllow_UserMode_EncryptedCA_NoCAPassphrase(t *testing.T) {
	t.Setenv("CERTHOLD_CA_PASSPHRASE", "")
	t.Setenv("CERTHOLD_PEER_PASSPHRASE", "peer-secret")

	dataDir := t.TempDir()
	caObj, err := ca.GenerateWithPassphrase(filepath.Join(dataDir, "ca"), []byte("ca-secret"))
	if err != nil {
		t.Fatalf("ca.GenerateWithPassphrase: %v", err)
	}
	dbPath := filepath.Join(dataDir, "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	if err := d.InsertPeerWithMode(ctx, "vmU", 1, "fp", []byte("k"), db.ModeUser, "alice", 1); err != nil {
		t.Fatalf("InsertPeerWithMode: %v", err)
	}
	if err := d.EnsureGroup(ctx, "infra"); err != nil {
		t.Fatalf("EnsureGroup: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "vmU", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups: %v", err)
	}
	d.Close()

	caTrim := strings.TrimRight(string(caObj.PublicKeyAuthorizedKey()), "\n")
	existing := []byte(`cert-authority,principals="manager,infra" ` + caTrim + "\n")
	fp := &fakePusher{readData: map[string][]byte{
		"/home/alice/.ssh/authorized_keys": existing,
	}}
	prev := groupDial
	groupDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		return fp, nil
	}
	t.Cleanup(func() { groupDial = prev })

	out, err := runGroupUserModeCmd(t, dataDir, dbPath, "allow", "db", "--on", "vmU")
	if err != nil {
		t.Fatalf("group allow against encrypted CA without CA passphrase: err=%v out=%s", err, out)
	}

	var wrote bool
	for _, c := range fp.Calls() {
		if c.op == "write" && strings.Contains(string(c.content), `principals="manager,infra,db"`) {
			wrote = true
		}
	}
	if !wrote {
		t.Errorf("expected authorized_keys rewrite with db added; calls=%+v", fp.Calls())
	}
}

// TestGroupAllow_V2Root_RewritesAuthorizedKeys_NoReload asserts a v2 root peer
// takes the user-mode RewritePrincipals branch on /root/.ssh/authorized_keys and
// does NOT touch auth_principals/root or reload sshd.
func TestGroupAllow_V2Root_RewritesAuthorizedKeys_NoReload(t *testing.T) {
	dataDir := t.TempDir()
	caObj, err := ca.Generate(filepath.Join(dataDir, "ca"))
	if err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	dbPath := filepath.Join(dataDir, "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	if err := d.InsertPeerWithMode(ctx, "vmV2R", 1, "fp", []byte("k"), db.ModeRoot, "", 2); err != nil {
		t.Fatalf("InsertPeerWithMode: %v", err)
	}
	if err := d.EnsureGroup(ctx, "infra"); err != nil {
		t.Fatalf("EnsureGroup: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "vmV2R", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups: %v", err)
	}
	d.Close()

	caTrim := strings.TrimRight(string(caObj.PublicKeyAuthorizedKey()), "\n")
	existing := []byte(`cert-authority,principals="manager,infra" ` + caTrim + "\n")
	fp := &fakePusher{readData: map[string][]byte{
		"/root/.ssh/authorized_keys": existing,
	}}
	prev := groupDial
	groupDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		return fp, nil
	}
	t.Cleanup(func() { groupDial = prev })

	out, err := runGroupUserModeCmd(t, dataDir, dbPath, "allow", "db", "--on", "vmV2R")
	if err != nil {
		t.Fatalf("allow: err=%v out=%s", err, out)
	}

	var ops []string
	var writeCall *fakePushCall
	calls := fp.Calls()
	for i := range calls {
		ops = append(ops, calls[i].op)
		if calls[i].op == "write" {
			writeCall = &calls[i]
		}
	}
	if !reflect.DeepEqual(ops, []string{"read", "write", "verify"}) {
		t.Errorf("ops = %v, want [read write verify] (no reload)", ops)
	}
	if writeCall == nil || writeCall.path != "/root/.ssh/authorized_keys" {
		t.Fatalf("write must target /root/.ssh/authorized_keys; got %+v", writeCall)
	}
	if !strings.Contains(string(writeCall.content), `principals="manager,infra,db"`) {
		t.Errorf("rewritten authorized_keys wrong: %q", writeCall.content)
	}
}

func TestGroupAllowRequiresOnFlag(t *testing.T) {
	dbPath := seedGroupDB(t, nil)
	installFakePusher(t)
	if _, err := runGroupCmd(t, dbPath, "allow", "g"); err == nil {
		t.Fatal("expected error when --on is missing")
	}
}
