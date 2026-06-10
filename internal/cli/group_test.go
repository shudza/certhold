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

// caLineFor returns a cert-authority authorized_keys line for the given
// principals carrying the CA pubkey at dataDir/ca, matching what
// peerfiles.BuildUser installs and what group's RewritePrincipals reads back.
// It reads ca.pub (no passphrase needed) so it works against encrypted CAs.
func caLineFor(t *testing.T, dataDir string, principals ...string) []byte {
	t.Helper()
	caPub, err := ca.LoadPublicKey(filepath.Join(dataDir, "ca"))
	if err != nil {
		t.Fatalf("ca.LoadPublicKey: %v", err)
	}
	caTrim := strings.TrimRight(string(caPub), "\n")
	return []byte(`cert-authority,principals="` + strings.Join(principals, ",") + `" ` + caTrim + "\n")
}

// installFakePusher installs a fake group dialer whose ReadFile serves the given
// existing authorized_keys at the v2 user path /home/alice/.ssh/authorized_keys.
func installFakePusher(t *testing.T, dataDir string, existing []byte) *fakePusher {
	t.Helper()
	fp := &fakePusher{readData: map[string][]byte{
		"/home/alice/.ssh/authorized_keys": existing,
	}}
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

func installFakePusherCapturingHost(t *testing.T, dataDir string, gotHost *string) *fakePusher {
	t.Helper()
	fp := &fakePusher{readData: map[string][]byte{
		"/home/alice/.ssh/authorized_keys": caLineFor(t, dataDir, "manager", "a"),
	}}
	prev := groupDial
	groupDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		*gotHost = host
		return fp, nil
	}
	t.Cleanup(func() { groupDial = prev })
	return fp
}

func TestGroupDialsAddressWhenNoHostFlag(t *testing.T) {
	dataDir, dbPath := seedGroupDB(t, []string{"a"})
	preCreateGroups(t, dbPath, "c")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := d.SetPeerAddress(context.Background(), "peer1", "10.0.0.9"); err != nil {
		t.Fatalf("SetPeerAddress: %v", err)
	}
	d.Close()

	var gotHost string
	installFakePusherCapturingHost(t, dataDir, &gotHost)
	if out, err := runGroupCmd(t, dataDir, dbPath, "allow", "c", "--on", "peer1"); err != nil {
		t.Fatalf("allow: err=%v out=%s", err, out)
	}
	if gotHost != "10.0.0.9" {
		t.Errorf("dialed host = %q, want 10.0.0.9 (the peer address)", gotHost)
	}
}

func TestGroupHostFlagBeatsAddress(t *testing.T) {
	dataDir, dbPath := seedGroupDB(t, []string{"a"})
	preCreateGroups(t, dbPath, "c")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := d.SetPeerAddress(context.Background(), "peer1", "10.0.0.9"); err != nil {
		t.Fatalf("SetPeerAddress: %v", err)
	}
	d.Close()

	var gotHost string
	installFakePusherCapturingHost(t, dataDir, &gotHost)
	if out, err := runGroupCmd(t, dataDir, dbPath, "allow", "c", "--on", "peer1", "--host", "explicit.host"); err != nil {
		t.Fatalf("allow: err=%v out=%s", err, out)
	}
	if gotHost != "explicit.host" {
		t.Errorf("dialed host = %q, want explicit.host (--host overrides address)", gotHost)
	}
}

func TestGroupDialsNameWhenNoAddress(t *testing.T) {
	dataDir, dbPath := seedGroupDB(t, []string{"a"})
	preCreateGroups(t, dbPath, "c")
	var gotHost string
	installFakePusherCapturingHost(t, dataDir, &gotHost)
	if out, err := runGroupCmd(t, dataDir, dbPath, "allow", "c", "--on", "peer1"); err != nil {
		t.Fatalf("allow: err=%v out=%s", err, out)
	}
	if gotHost != "peer1" {
		t.Errorf("dialed host = %q, want peer1 (the name, no address set)", gotHost)
	}
}

// seedGroupDB sets up a data-dir with a CA and a single layout-v2 user-mode peer
// "peer1" (target_user=alice) carrying the given allowed groups.
func seedGroupDB(t *testing.T, allowed []string) (dataDir, dbPath string) {
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
	ctx := context.Background()
	if err := d.InsertPeer(ctx, "peer1", 1, "fp", []byte("k"), "alice", true, ""); err != nil {
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
	return dataDir, dbPath
}

func runGroupCmd(t *testing.T, dataDir, dbPath string, args ...string) (string, error) {
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

// writeContaining returns the content of the single write call (failing if there
// is not exactly one).
func writeContent(t *testing.T, calls []fakePushCall) []byte {
	t.Helper()
	var w *fakePushCall
	for i := range calls {
		if calls[i].op == "write" {
			w = &calls[i]
			break
		}
	}
	if w == nil {
		t.Fatalf("no write call in %+v", calls)
	}
	return w.content
}

func TestGroupAllowAddsAndPushes(t *testing.T) {
	dataDir, dbPath := seedGroupDB(t, []string{"a", "b"})
	preCreateGroups(t, dbPath, "c")
	fp := installFakePusher(t, dataDir, caLineFor(t, dataDir, "manager", "a", "b"))

	out, err := runGroupCmd(t, dataDir, dbPath, "allow", "c", "--on", "peer1")
	if err != nil {
		t.Fatalf("allow: err=%v out=%s", err, out)
	}

	got := getAllowed(t, dbPath)
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("allowed = %v, want %v", got, want)
	}

	calls := fp.Calls()
	// Expect read, write, verify — NO reload.
	var ops []string
	for _, c := range calls {
		ops = append(ops, c.op)
	}
	if !reflect.DeepEqual(ops, []string{"read", "write", "verify"}) {
		t.Fatalf("ops = %v, want [read write verify]: %+v", ops, calls)
	}
	var writeCall *fakePushCall
	for i := range calls {
		if calls[i].op == "write" {
			writeCall = &calls[i]
		}
	}
	if writeCall.path != "/home/alice/.ssh/authorized_keys" {
		t.Errorf("write path = %q, want /home/alice/.ssh/authorized_keys", writeCall.path)
	}
	if !strings.Contains(string(writeCall.content), `cert-authority,principals="manager,a,b,c" `) {
		t.Errorf("content = %q, want principals manager,a,b,c", writeCall.content)
	}
	if writeCall.mode != fs.FileMode(0644) {
		t.Errorf("mode = %o, want 0644", writeCall.mode)
	}
}

func TestGroupDisallowRemovesAndPushes(t *testing.T) {
	dataDir, dbPath := seedGroupDB(t, []string{"a", "b", "c"})
	fp := installFakePusher(t, dataDir, caLineFor(t, dataDir, "manager", "a", "b", "c"))

	out, err := runGroupCmd(t, dataDir, dbPath, "disallow", "a", "--on", "peer1")
	if err != nil {
		t.Fatalf("disallow: err=%v out=%s", err, out)
	}

	got := getAllowed(t, dbPath)
	want := []string{"b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("allowed = %v, want %v", got, want)
	}

	if !strings.Contains(string(writeContent(t, fp.Calls())), `cert-authority,principals="manager,b,c" `) {
		t.Errorf("content = %q, want principals manager,b,c", writeContent(t, fp.Calls()))
	}
}

func TestGroupAllowIdempotent(t *testing.T) {
	dataDir, dbPath := seedGroupDB(t, []string{"a", "b", "c"})
	fp := installFakePusher(t, dataDir, caLineFor(t, dataDir, "manager", "a", "b", "c"))

	out, err := runGroupCmd(t, dataDir, dbPath, "allow", "c", "--on", "peer1")
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
	dataDir, dbPath := seedGroupDB(t, []string{"a", "b"})
	fp := installFakePusher(t, dataDir, caLineFor(t, dataDir, "manager", "a", "b"))

	out, err := runGroupCmd(t, dataDir, dbPath, "disallow", "z", "--on", "peer1")
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
	dataDir, dbPath := seedGroupDB(t, nil)
	preCreateGroups(t, dbPath, "x")
	fp := installFakePusher(t, dataDir, caLineFor(t, dataDir, "manager"))

	if _, err := runGroupCmd(t, dataDir, dbPath, "allow", "x", "--on", "peer1"); err != nil {
		t.Fatalf("allow: %v", err)
	}
	content := writeContent(t, fp.Calls())
	if !strings.HasPrefix(string(content), `cert-authority,principals="manager,x" `) {
		t.Errorf("content = %q, want principals starting manager,x", content)
	}
}

func TestGroupAllowMissingPeer(t *testing.T) {
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	d.Close()
	installFakePusher(t, dataDir, nil)

	if _, err := runGroupCmd(t, dataDir, dbPath, "allow", "g", "--on", "missing"); err == nil {
		t.Fatal("expected error for missing peer")
	}
}

func TestGroupSSHOptionsPathsMatchInitLayout(t *testing.T) {
	t.Setenv("CERTHOLD_CA_PASSPHRASE", "test-ca-pw")
	t.Setenv("CERTHOLD_PEER_PASSPHRASE", "test-peer-pw")
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "state.db")

	// init writes a v2 manager self identity under self/root/.ssh.
	hostname := "mgr"
	initCmd := NewRootCmd()
	var initOut bytes.Buffer
	initCmd.SetOut(&initOut)
	initCmd.SetErr(&initOut)
	initCmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", hostname, "--user", "root", "--listen-ip", "127.0.0.1", "--no-prompt"})
	if err := initCmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("init: %v\n%s", err, initOut.String())
	}
	origHostname := osHostname
	osHostname = func() (string, error) { return hostname, nil }
	t.Cleanup(func() { osHostname = origHostname })

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := d.InsertPeer(context.Background(), "peer1", 1, "fp", []byte("k"), "alice", true, ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	key, _, _ := d.GetMeta(context.Background(), db.MetaInstanceKey)
	d.Close()
	preCreateGroups(t, dbPath, "g")

	var captured sshpush.Options
	fp := installFakePusherCapturingOpts(t, &captured)
	fp.readData = map[string][]byte{"/home/alice/.ssh/authorized_keys": caLineFor(t, dataDir, "manager")}

	if out, err := runGroupCmd(t, dataDir, dbPath, "allow", "g", "--on", "peer1"); err != nil {
		t.Fatalf("allow: err=%v out=%s", err, out)
	}

	base := filepath.Join(dataDir, "self", "root", ".ssh")
	wantCert := filepath.Join(base, "id_ed25519_"+key+"-cert.pub")
	wantKey := filepath.Join(base, "id_ed25519_"+key)
	wantKH := filepath.Join(base, "known_hosts")

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
	if err := d.InsertPeer(context.Background(), peerName, 1, "fp", []byte("k"), targetUser, true, ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
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
	preCreateGroups(t, dbPath, "db")

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
	if err := d.InsertPeer(ctx, "vmU", 1, "fp", []byte("k"), "alice", true, ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	if err := d.EnsureGroup(ctx, "infra"); err != nil {
		t.Fatalf("EnsureGroup: %v", err)
	}
	if err := d.EnsureGroup(ctx, "db"); err != nil {
		t.Fatalf("EnsureGroup db: %v", err)
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

// TestGroupAllow_RootUser_RewritesAuthorizedKeys_NoReload asserts a
// root-targeting (target_user=root) peer takes the RewritePrincipals branch on
// /root/.ssh/authorized_keys and does NOT touch auth_principals/root or reload.
func TestGroupAllow_RootUser_RewritesAuthorizedKeys_NoReload(t *testing.T) {
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
	if err := d.InsertPeer(ctx, "vmRoot", 1, "fp", []byte("k"), "root", true, ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	if err := d.EnsureGroup(ctx, "infra"); err != nil {
		t.Fatalf("EnsureGroup: %v", err)
	}
	if err := d.EnsureGroup(ctx, "db"); err != nil {
		t.Fatalf("EnsureGroup db: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "vmRoot", []string{"infra"}); err != nil {
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

	out, err := runGroupUserModeCmd(t, dataDir, dbPath, "allow", "db", "--on", "vmRoot")
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
	dataDir, dbPath := seedGroupDB(t, nil)
	installFakePusher(t, dataDir, nil)
	if _, err := runGroupCmd(t, dataDir, dbPath, "allow", "g"); err == nil {
		t.Fatal("expected error when --on is missing")
	}
}

// TestGroupAllow_FailsWhenGroupDoesNotExist asserts the allow path rejects an
// unknown group, never dials a pusher, and leaves the peer's allowed list
// untouched.
func TestGroupAllow_FailsWhenGroupDoesNotExist(t *testing.T) {
	dataDir, dbPath := seedGroupDB(t, []string{"a"})
	dialCount := 0
	prev := groupDial
	groupDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		dialCount++
		return &fakePusher{}, nil
	}
	t.Cleanup(func() { groupDial = prev })

	out, err := runGroupCmd(t, dataDir, dbPath, "allow", "nonexistent", "--on", "peer1")
	if err == nil {
		t.Fatal("expected allow to fail for nonexistent group, got nil")
	}
	msg := err.Error() + out
	if !strings.Contains(msg, "nonexistent") {
		t.Errorf("error %q does not mention group name", msg)
	}
	if !strings.Contains(msg, "group create") {
		t.Errorf("error %q does not guide user to `group create`", msg)
	}
	if dialCount != 0 {
		t.Errorf("expected no pusher dials, got %d", dialCount)
	}
	got := getAllowed(t, dbPath)
	if !reflect.DeepEqual(got, []string{"a"}) {
		t.Errorf("allowed = %v, want [a] (unchanged)", got)
	}
}

// freshGroupDB makes an empty data-dir + db with no peers/groups.
func freshGroupDB(t *testing.T) (dataDir, dbPath string) {
	t.Helper()
	dataDir = t.TempDir()
	dbPath = filepath.Join(dataDir, "state.db")
	return dataDir, dbPath
}

func TestGroupCreate_Success(t *testing.T) {
	dataDir, dbPath := freshGroupDB(t)
	out, err := runGroupCmd(t, dataDir, dbPath, "create", "infra")
	if err != nil {
		t.Fatalf("create: err=%v out=%s", err, out)
	}
	if !strings.Contains(out, `group "infra" created`) {
		t.Errorf("output = %q, want it to contain 'group \"infra\" created'", out)
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	ok, err := d.GroupExists(context.Background(), "infra")
	if err != nil {
		t.Fatalf("GroupExists: %v", err)
	}
	if !ok {
		t.Error("expected group 'infra' to exist after create")
	}
}

func TestGroupCreate_Duplicate(t *testing.T) {
	dataDir, dbPath := freshGroupDB(t)
	if _, err := runGroupCmd(t, dataDir, dbPath, "create", "infra"); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := runGroupCmd(t, dataDir, dbPath, "create", "infra")
	if err == nil {
		t.Fatal("expected error on duplicate create")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %q, want it to mention 'already exists'", err)
	}
}

func TestGroupCreate_Reserved(t *testing.T) {
	dataDir, dbPath := freshGroupDB(t)

	// Open the DB before to capture baseline state, then close.
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	before, err := d.ListGroupsWithPeerCount(context.Background())
	if err != nil {
		t.Fatalf("ListGroupsWithPeerCount: %v", err)
	}
	d.Close()

	_, err = runGroupCmd(t, dataDir, dbPath, "create", "manager")
	if err == nil {
		t.Fatal("expected error creating reserved 'manager' group")
	}
	if !strings.Contains(err.Error(), "reserved") {
		t.Errorf("error = %q, want it to mention 'reserved'", err)
	}

	d, err = db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open after: %v", err)
	}
	defer d.Close()
	after, err := d.ListGroupsWithPeerCount(context.Background())
	if err != nil {
		t.Fatalf("ListGroupsWithPeerCount after: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Errorf("groups changed: before=%v after=%v", before, after)
	}
	if ok, _ := d.GroupExists(context.Background(), "manager"); ok {
		t.Error("manager group should not exist after rejected create")
	}
}

func TestGroupShow_Missing(t *testing.T) {
	dataDir, dbPath := freshGroupDB(t)
	_, err := runGroupCmd(t, dataDir, dbPath, "show", "nope")
	if err == nil {
		t.Fatal("expected error for missing group")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error = %q, want it to mention 'does not exist'", err)
	}
}

func TestGroupShow_HappyPath(t *testing.T) {
	dataDir, dbPath := freshGroupDB(t)

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	if err := d.CreateGroup(ctx, "infra"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := d.InsertPeer(ctx, "alpha", 1, "fp1", []byte("k"), "alice", true, ""); err != nil {
		t.Fatalf("InsertPeer alpha: %v", err)
	}
	if err := d.InsertPeer(ctx, "beta", 1, "fp2", []byte("k"), "bob", true, ""); err != nil {
		t.Fatalf("InsertPeer beta: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "alpha", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerGroups alpha: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "beta", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups beta: %v", err)
	}
	d.Close()

	out, err := runGroupCmd(t, dataDir, dbPath, "show", "infra")
	if err != nil {
		t.Fatalf("show: err=%v out=%s", err, out)
	}
	if !strings.Contains(out, "GROUP") || !strings.Contains(out, "infra") {
		t.Errorf("output missing GROUP/infra: %q", out)
	}
	lines := strings.Split(out, "\n")
	var membersLine, allowedLine string
	for _, ln := range lines {
		switch {
		case strings.HasPrefix(ln, "MEMBERS"):
			membersLine = ln
		case strings.HasPrefix(ln, "ALLOWED BY"):
			allowedLine = ln
		}
	}
	if !strings.Contains(membersLine, "alpha") {
		t.Errorf("MEMBERS line = %q, want it to include 'alpha'", membersLine)
	}
	if !strings.Contains(allowedLine, "beta") {
		t.Errorf("ALLOWED BY line = %q, want it to include 'beta'", allowedLine)
	}
}

func TestGroupShow_NoMembers(t *testing.T) {
	dataDir, dbPath := freshGroupDB(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := d.CreateGroup(context.Background(), "lonely"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	d.Close()

	out, err := runGroupCmd(t, dataDir, dbPath, "show", "lonely")
	if err != nil {
		t.Fatalf("show: err=%v out=%s", err, out)
	}
	lines := strings.Split(out, "\n")
	var membersLine, allowedLine string
	for _, ln := range lines {
		switch {
		case strings.HasPrefix(ln, "MEMBERS"):
			membersLine = ln
		case strings.HasPrefix(ln, "ALLOWED BY"):
			allowedLine = ln
		}
	}
	if !strings.Contains(membersLine, "(none)") {
		t.Errorf("MEMBERS line = %q, want '(none)'", membersLine)
	}
	if !strings.Contains(allowedLine, "(none)") {
		t.Errorf("ALLOWED BY line = %q, want '(none)'", allowedLine)
	}
}

func TestGroupCreate_RoundTripsToShow(t *testing.T) {
	dataDir, dbPath := freshGroupDB(t)
	if _, err := runGroupCmd(t, dataDir, dbPath, "create", "x"); err != nil {
		t.Fatalf("create: %v", err)
	}
	out, err := runGroupCmd(t, dataDir, dbPath, "show", "x")
	if err != nil {
		t.Fatalf("show: err=%v out=%s", err, out)
	}
	if !strings.Contains(out, "GROUP") || !strings.Contains(out, "x") {
		t.Errorf("output missing GROUP/x: %q", out)
	}
	if strings.Count(out, "(none)") < 2 {
		t.Errorf("expected MEMBERS and ALLOWED BY both '(none)'; got %q", out)
	}
}

// installFakePusherFor installs a fake group dialer that returns the same
// pusher for every dial. readData is shared across dials so per-peer
// authorized_keys content can be pre-seeded by path.
func installFakePusherFor(t *testing.T, fp *fakePusher) {
	t.Helper()
	prev := groupDial
	groupDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		return fp, nil
	}
	t.Cleanup(func() { groupDial = prev })
}

// freshPeerKey mints an ssh-ed25519 keypair and returns the authorized_key
// bytes suitable for db.InsertPeer's authorizedKey argument.
func freshPeerKey(t *testing.T) []byte {
	t.Helper()
	_, pubAK, _, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	return pubAK
}

func TestGroupDelete_NoAffectedPeers(t *testing.T) {
	dataDir, dbPath := freshGroupDB(t)
	if _, err := runGroupCmd(t, dataDir, dbPath, "create", "x"); err != nil {
		t.Fatalf("create: %v", err)
	}

	fp := &fakePusher{}
	installFakePusherFor(t, fp)

	out, err := runGroupCmd(t, dataDir, dbPath, "delete", "x")
	if err != nil {
		t.Fatalf("delete: err=%v out=%s", err, out)
	}
	if !strings.Contains(out, "no peers affected") {
		t.Errorf("output = %q, want it to contain 'no peers affected'", out)
	}
	if len(fp.Calls()) != 0 {
		t.Errorf("expected no pusher calls, got %d: %+v", len(fp.Calls()), fp.Calls())
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	if ok, _ := d.GroupExists(context.Background(), "x"); ok {
		t.Error("group 'x' should no longer exist")
	}
}

func TestGroupDelete_Reserved(t *testing.T) {
	dataDir, dbPath := freshGroupDB(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := d.CreateGroup(context.Background(), "infra"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	d.Close()

	fp := &fakePusher{}
	installFakePusherFor(t, fp)

	_, err = runGroupCmd(t, dataDir, dbPath, "delete", "manager")
	if err == nil {
		t.Fatal("expected error deleting reserved 'manager' group")
	}
	if !strings.Contains(err.Error(), "reserved") {
		t.Errorf("error = %q, want it to mention 'reserved'", err)
	}
	if len(fp.Calls()) != 0 {
		t.Errorf("expected no pusher calls, got %d", len(fp.Calls()))
	}

	d, err = db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	if ok, _ := d.GroupExists(context.Background(), "infra"); !ok {
		t.Error("untouched group 'infra' should still exist")
	}
}

func TestGroupDelete_NotFound(t *testing.T) {
	dataDir, dbPath := freshGroupDB(t)

	fp := &fakePusher{}
	installFakePusherFor(t, fp)

	_, err := runGroupCmd(t, dataDir, dbPath, "delete", "nope")
	if err == nil {
		t.Fatal("expected error deleting nonexistent group")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error = %q, want it to mention 'does not exist'", err)
	}
	if len(fp.Calls()) != 0 {
		t.Errorf("expected no pusher calls, got %d", len(fp.Calls()))
	}
}

func TestGroupDelete_CascadesMembershipAndAllowList(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := ca.Generate(filepath.Join(dataDir, "ca")); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	dbPath := filepath.Join(dataDir, "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	for _, g := range []string{"web", "infra"} {
		if err := d.EnsureGroup(ctx, g); err != nil {
			t.Fatalf("EnsureGroup %s: %v", g, err)
		}
	}
	alphaKey := freshPeerKey(t)
	betaKey := freshPeerKey(t)
	gammaKey := freshPeerKey(t)
	if err := d.InsertPeer(ctx, "alpha", 1, "fp-a", alphaKey, "alice", true, ""); err != nil {
		t.Fatalf("InsertPeer alpha: %v", err)
	}
	if err := d.InsertPeer(ctx, "beta", 1, "fp-b", betaKey, "bob", true, ""); err != nil {
		t.Fatalf("InsertPeer beta: %v", err)
	}
	if err := d.InsertPeer(ctx, "gamma", 1, "fp-g", gammaKey, "carol", true, ""); err != nil {
		t.Fatalf("InsertPeer gamma: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "alpha", []string{"web", "infra"}); err != nil {
		t.Fatalf("SetPeerGroups alpha: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "beta", []string{"web", "infra"}); err != nil {
		t.Fatalf("SetPeerGroups beta: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "gamma", []string{"web", "infra"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups gamma: %v", err)
	}
	d.Close()

	fp := &fakePusher{readData: map[string][]byte{
		"/home/carol/.ssh/authorized_keys": caLineFor(t, dataDir, "manager", "web", "infra"),
	}}
	installFakePusherFor(t, fp)

	out, err := runGroupCmd(t, dataDir, dbPath, "delete", "web")
	if err != nil {
		t.Fatalf("delete: err=%v out=%s", err, out)
	}
	if !strings.Contains(out, "affected peers:") {
		t.Errorf("output = %q, want it to mention 'affected peers:'", out)
	}

	d, err = db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	if ok, _ := d.GroupExists(ctx, "web"); ok {
		t.Error("group 'web' should no longer exist")
	}
	for _, name := range []string{"alpha", "beta"} {
		got, err := d.GetPeerGroups(ctx, name)
		if err != nil {
			t.Fatalf("GetPeerGroups %s: %v", name, err)
		}
		want := []string{"infra"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("GetPeerGroups(%s) = %v, want %v", name, got, want)
		}
	}
	gammaAllowed, err := d.GetPeerAllowedGroups(ctx, "gamma")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups gamma: %v", err)
	}
	if !reflect.DeepEqual(gammaAllowed, []string{"infra"}) {
		t.Errorf("gamma allowed = %v, want [infra]", gammaAllowed)
	}

	calls := fp.Calls()
	var certWrites, akWrites, verifies int
	for _, c := range calls {
		switch {
		case c.op == "write" && strings.HasSuffix(c.path, "-cert.pub"):
			certWrites++
		case c.op == "write" && strings.HasSuffix(c.path, "/authorized_keys"):
			akWrites++
		case c.op == "verify":
			verifies++
		}
	}
	if certWrites < 2 {
		t.Errorf("want >=2 cert writes (alpha+beta), got %d. calls=%+v", certWrites, calls)
	}
	if akWrites < 1 {
		t.Errorf("want >=1 authorized_keys write (gamma), got %d. calls=%+v", akWrites, calls)
	}
	if verifies < 3 {
		t.Errorf("want 3 verify calls (one per peer), got %d", verifies)
	}
}

func TestGroupDelete_StragglerKeepsGroup(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := ca.Generate(filepath.Join(dataDir, "ca")); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	dbPath := filepath.Join(dataDir, "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	if err := d.EnsureGroup(ctx, "web"); err != nil {
		t.Fatalf("EnsureGroup web: %v", err)
	}
	alphaKey := freshPeerKey(t)
	if err := d.InsertPeer(ctx, "alpha", 1, "fp-a", alphaKey, "alice", true, ""); err != nil {
		t.Fatalf("InsertPeer alpha: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "alpha", []string{"web"}); err != nil {
		t.Fatalf("SetPeerGroups alpha: %v", err)
	}
	d.Close()

	fp := &fakePusher{errOn: "verify"}
	installFakePusherFor(t, fp)

	_, err = runGroupCmd(t, dataDir, dbPath, "delete", "web")
	if err == nil {
		t.Fatal("expected straggler error")
	}
	if !strings.Contains(err.Error(), "straggler") {
		t.Errorf("error = %q, want it to mention 'straggler'", err)
	}

	d, err = db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	if ok, _ := d.GroupExists(ctx, "web"); !ok {
		t.Error("group 'web' should still exist after straggler")
	}
	got, err := d.GetPeerGroups(ctx, "alpha")
	if err != nil {
		t.Fatalf("GetPeerGroups alpha: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("GetPeerGroups(alpha) = %v, want [] (DB updated for attempted peer)", got)
	}
}

// seedRenameDB sets up a CA + DB pre-populated with the requested groups and
// peers, including memberships and allow-lists. Each peer gets a fresh
// authorized_key so SignCert can re-issue against it.
func seedRenameDB(t *testing.T) (dataDir, dbPath string) {
	t.Helper()
	dataDir = t.TempDir()
	if _, err := ca.Generate(filepath.Join(dataDir, "ca")); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	dbPath = filepath.Join(dataDir, "state.db")
	return dataDir, dbPath
}

func TestGroupRename_Success(t *testing.T) {
	dataDir, dbPath := seedRenameDB(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	if err := d.EnsureGroup(ctx, "web"); err != nil {
		t.Fatalf("EnsureGroup web: %v", err)
	}
	alphaKey := freshPeerKey(t)
	betaKey := freshPeerKey(t)
	gammaKey := freshPeerKey(t)
	if err := d.InsertPeer(ctx, "alpha", 1, "fp-a", alphaKey, "alice", true, ""); err != nil {
		t.Fatalf("InsertPeer alpha: %v", err)
	}
	if err := d.InsertPeer(ctx, "beta", 1, "fp-b", betaKey, "bob", true, ""); err != nil {
		t.Fatalf("InsertPeer beta: %v", err)
	}
	if err := d.InsertPeer(ctx, "gamma", 1, "fp-g", gammaKey, "carol", true, ""); err != nil {
		t.Fatalf("InsertPeer gamma: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "alpha", []string{"web"}); err != nil {
		t.Fatalf("SetPeerGroups alpha: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "beta", []string{"web"}); err != nil {
		t.Fatalf("SetPeerGroups beta: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "gamma", []string{"web"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups gamma: %v", err)
	}
	d.Close()

	fp := &fakePusher{readData: map[string][]byte{
		"/home/carol/.ssh/authorized_keys": caLineFor(t, dataDir, "manager", "web"),
	}}
	installFakePusherFor(t, fp)

	out, err := runGroupCmd(t, dataDir, dbPath, "rename", "web", "public")
	if err != nil {
		t.Fatalf("rename: err=%v out=%s", err, out)
	}
	if !strings.Contains(out, "renamed") || !strings.Contains(out, "public") {
		t.Errorf("output = %q, want 'renamed' and 'public'", out)
	}

	d, err = db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open after: %v", err)
	}
	defer d.Close()
	if ok, _ := d.GroupExists(ctx, "web"); ok {
		t.Error("group 'web' should no longer exist")
	}
	if ok, _ := d.GroupExists(ctx, "public"); !ok {
		t.Error("group 'public' should exist after rename")
	}
	for _, name := range []string{"alpha", "beta"} {
		got, err := d.GetPeerGroups(ctx, name)
		if err != nil {
			t.Fatalf("GetPeerGroups %s: %v", name, err)
		}
		if !reflect.DeepEqual(got, []string{"public"}) {
			t.Errorf("GetPeerGroups(%s) = %v, want [public]", name, got)
		}
	}
	gammaAllowed, err := d.GetPeerAllowedGroups(ctx, "gamma")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups gamma: %v", err)
	}
	if !reflect.DeepEqual(gammaAllowed, []string{"public"}) {
		t.Errorf("gamma allowed = %v, want [public]", gammaAllowed)
	}

	calls := fp.Calls()
	var certWrites, akWrites int
	var akContent []byte
	for _, c := range calls {
		switch {
		case c.op == "write" && strings.HasSuffix(c.path, "-cert.pub"):
			certWrites++
		case c.op == "write" && strings.HasSuffix(c.path, "/authorized_keys"):
			akWrites++
			akContent = c.content
		}
	}
	if certWrites != 2 {
		t.Errorf("cert writes = %d, want 2 (alpha+beta). calls=%+v", certWrites, calls)
	}
	if akWrites != 1 {
		t.Errorf("authorized_keys writes = %d, want 1 (gamma)", akWrites)
	}
	if !strings.Contains(string(akContent), `principals="manager,public"`) {
		t.Errorf("rewritten authorized_keys = %q, want it to contain 'principals=\"manager,public\"' (and no 'web')", akContent)
	}
	if strings.Contains(string(akContent), "web") {
		t.Errorf("rewritten authorized_keys still contains 'web': %q", akContent)
	}
}

func TestGroupRename_TargetExists(t *testing.T) {
	dataDir, dbPath := seedRenameDB(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	if err := d.EnsureGroup(ctx, "web"); err != nil {
		t.Fatalf("EnsureGroup web: %v", err)
	}
	if err := d.EnsureGroup(ctx, "public"); err != nil {
		t.Fatalf("EnsureGroup public: %v", err)
	}
	alphaKey := freshPeerKey(t)
	if err := d.InsertPeer(ctx, "alpha", 1, "fp-a", alphaKey, "alice", true, ""); err != nil {
		t.Fatalf("InsertPeer alpha: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "alpha", []string{"web"}); err != nil {
		t.Fatalf("SetPeerGroups alpha: %v", err)
	}
	d.Close()

	fp := &fakePusher{}
	installFakePusherFor(t, fp)

	_, err = runGroupCmd(t, dataDir, dbPath, "rename", "web", "public")
	if err == nil {
		t.Fatal("expected error when target exists")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %q, want it to mention 'already exists'", err)
	}
	if len(fp.Calls()) != 0 {
		t.Errorf("expected no pusher calls, got %d: %+v", len(fp.Calls()), fp.Calls())
	}

	d, err = db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open after: %v", err)
	}
	defer d.Close()
	if ok, _ := d.GroupExists(ctx, "web"); !ok {
		t.Error("group 'web' should still exist after rejected rename")
	}
	got, err := d.GetPeerGroups(ctx, "alpha")
	if err != nil {
		t.Fatalf("GetPeerGroups alpha: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"web"}) {
		t.Errorf("GetPeerGroups(alpha) = %v, want [web]", got)
	}
}

func TestGroupRename_SourceMissing(t *testing.T) {
	dataDir, dbPath := freshGroupDB(t)
	fp := &fakePusher{}
	installFakePusherFor(t, fp)

	_, err := runGroupCmd(t, dataDir, dbPath, "rename", "web", "public")
	if err == nil {
		t.Fatal("expected error for missing source group")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error = %q, want it to mention 'does not exist'", err)
	}
	if len(fp.Calls()) != 0 {
		t.Errorf("expected no pusher calls, got %d", len(fp.Calls()))
	}
}

func TestGroupRename_InvalidNewName(t *testing.T) {
	dataDir, dbPath := freshGroupDB(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := d.EnsureGroup(context.Background(), "web"); err != nil {
		t.Fatalf("EnsureGroup web: %v", err)
	}
	d.Close()

	fp := &fakePusher{}
	installFakePusherFor(t, fp)

	_, err = runGroupCmd(t, dataDir, dbPath, "rename", "web", "   ")
	if err == nil {
		t.Fatal("expected error for invalid (whitespace) new name")
	}
	if !strings.Contains(err.Error(), "invalid group name") {
		t.Errorf("error = %q, want it to mention 'invalid group name'", err)
	}
	if len(fp.Calls()) != 0 {
		t.Errorf("expected no pusher calls, got %d", len(fp.Calls()))
	}

	d, err = db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open after: %v", err)
	}
	defer d.Close()
	if ok, _ := d.GroupExists(context.Background(), "web"); !ok {
		t.Error("group 'web' should still exist after rejected rename")
	}
}

func TestGroupRename_ReservedFromOrTo(t *testing.T) {
	for _, tc := range []struct {
		name, oldName, newName string
	}{
		{"reserved-from", "manager", "x"},
		{"reserved-to", "x", "manager"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir, dbPath := freshGroupDB(t)
			d, err := db.Open(dbPath)
			if err != nil {
				t.Fatalf("db.Open: %v", err)
			}
			if err := d.EnsureGroup(context.Background(), "x"); err != nil {
				t.Fatalf("EnsureGroup x: %v", err)
			}
			before, err := d.ListGroupsWithPeerCount(context.Background())
			if err != nil {
				t.Fatalf("ListGroupsWithPeerCount: %v", err)
			}
			d.Close()

			fp := &fakePusher{}
			installFakePusherFor(t, fp)

			_, err = runGroupCmd(t, dataDir, dbPath, "rename", tc.oldName, tc.newName)
			if err == nil {
				t.Fatal("expected error for reserved rename")
			}
			if !strings.Contains(err.Error(), "reserved") {
				t.Errorf("error = %q, want it to mention 'reserved'", err)
			}
			if len(fp.Calls()) != 0 {
				t.Errorf("expected no pusher calls, got %d", len(fp.Calls()))
			}

			d, err = db.Open(dbPath)
			if err != nil {
				t.Fatalf("db.Open after: %v", err)
			}
			after, err := d.ListGroupsWithPeerCount(context.Background())
			if err != nil {
				t.Fatalf("ListGroupsWithPeerCount after: %v", err)
			}
			d.Close()
			if !reflect.DeepEqual(before, after) {
				t.Errorf("groups changed: before=%v after=%v", before, after)
			}
		})
	}
}

func TestGroupRename_NoOpSameName(t *testing.T) {
	dataDir, dbPath := seedRenameDB(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	if err := d.EnsureGroup(ctx, "web"); err != nil {
		t.Fatalf("EnsureGroup web: %v", err)
	}
	alphaKey := freshPeerKey(t)
	if err := d.InsertPeer(ctx, "alpha", 1, "fp-a", alphaKey, "alice", true, ""); err != nil {
		t.Fatalf("InsertPeer alpha: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "alpha", []string{"web"}); err != nil {
		t.Fatalf("SetPeerGroups alpha: %v", err)
	}
	d.Close()

	fp := &fakePusher{}
	installFakePusherFor(t, fp)

	out, err := runGroupCmd(t, dataDir, dbPath, "rename", "web", "web")
	if err != nil {
		t.Fatalf("rename web→web: err=%v out=%s", err, out)
	}
	if len(fp.Calls()) != 0 {
		t.Errorf("expected no pusher calls for same-name rename, got %d: %+v", len(fp.Calls()), fp.Calls())
	}

	d, err = db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open after: %v", err)
	}
	defer d.Close()
	if ok, _ := d.GroupExists(ctx, "web"); !ok {
		t.Error("group 'web' should still exist after same-name rename")
	}
	got, err := d.GetPeerGroups(ctx, "alpha")
	if err != nil {
		t.Fatalf("GetPeerGroups alpha: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"web"}) {
		t.Errorf("alpha groups = %v, want [web]", got)
	}
}

func TestGroupRename_StragglerKeepsRenameCommitted(t *testing.T) {
	dataDir, dbPath := seedRenameDB(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	if err := d.EnsureGroup(ctx, "web"); err != nil {
		t.Fatalf("EnsureGroup web: %v", err)
	}
	alphaKey := freshPeerKey(t)
	if err := d.InsertPeer(ctx, "alpha", 1, "fp-a", alphaKey, "alice", true, ""); err != nil {
		t.Fatalf("InsertPeer alpha: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "alpha", []string{"web"}); err != nil {
		t.Fatalf("SetPeerGroups alpha: %v", err)
	}
	d.Close()

	fp := &fakePusher{errOn: "verify"}
	installFakePusherFor(t, fp)

	_, err = runGroupCmd(t, dataDir, dbPath, "rename", "web", "public")
	if err == nil {
		t.Fatal("expected straggler error")
	}
	if !strings.Contains(err.Error(), "straggler") {
		t.Errorf("error = %q, want it to mention 'straggler'", err)
	}

	d, err = db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open after: %v", err)
	}
	defer d.Close()
	if ok, _ := d.GroupExists(ctx, "web"); ok {
		t.Error("group 'web' should NOT exist (rename stays committed)")
	}
	if ok, _ := d.GroupExists(ctx, "public"); !ok {
		t.Error("group 'public' should exist (rename stays committed)")
	}
	got, err := d.GetPeerGroups(ctx, "alpha")
	if err != nil {
		t.Fatalf("GetPeerGroups alpha: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"public"}) {
		t.Errorf("alpha groups = %v, want [public]", got)
	}
}

func TestGroupRename_SkipsRevokedPeers(t *testing.T) {
	dataDir, dbPath := seedRenameDB(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	if err := d.EnsureGroup(ctx, "web"); err != nil {
		t.Fatalf("EnsureGroup web: %v", err)
	}
	aliveKey := freshPeerKey(t)
	deadKey := freshPeerKey(t)
	if err := d.InsertPeer(ctx, "alive", 1, "fp-l", aliveKey, "alice", true, ""); err != nil {
		t.Fatalf("InsertPeer alive: %v", err)
	}
	if err := d.InsertPeer(ctx, "dead", 1, "fp-d", deadKey, "bob", true, ""); err != nil {
		t.Fatalf("InsertPeer dead: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "alive", []string{"web"}); err != nil {
		t.Fatalf("SetPeerGroups alive: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "dead", []string{"web"}); err != nil {
		t.Fatalf("SetPeerGroups dead: %v", err)
	}
	if err := d.SetPeerRevoked(ctx, "dead"); err != nil {
		t.Fatalf("SetPeerRevoked dead: %v", err)
	}
	d.Close()

	var dialedHosts []string
	fp := &fakePusher{}
	prev := groupDial
	groupDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		dialedHosts = append(dialedHosts, host)
		return fp, nil
	}
	t.Cleanup(func() { groupDial = prev })

	out, err := runGroupCmd(t, dataDir, dbPath, "rename", "web", "public")
	if err != nil {
		t.Fatalf("rename: err=%v out=%s", err, out)
	}

	for _, h := range dialedHosts {
		if h == "dead" {
			t.Errorf("revoked peer 'dead' was dialed: %v", dialedHosts)
		}
	}
	if len(dialedHosts) != 1 || dialedHosts[0] != "alive" {
		t.Errorf("dialedHosts = %v, want [alive]", dialedHosts)
	}

	d, err = db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open after: %v", err)
	}
	defer d.Close()
	for _, name := range []string{"alive", "dead"} {
		got, err := d.GetPeerGroups(ctx, name)
		if err != nil {
			t.Fatalf("GetPeerGroups %s: %v", name, err)
		}
		if !reflect.DeepEqual(got, []string{"public"}) {
			t.Errorf("GetPeerGroups(%s) = %v, want [public] (RenameGroup updates all rows)", name, got)
		}
	}
	if ok, _ := d.GroupExists(ctx, "web"); ok {
		t.Error("group 'web' should not exist")
	}
	if ok, _ := d.GroupExists(ctx, "public"); !ok {
		t.Error("group 'public' should exist")
	}
}

func TestGroupDelete_SkipsRevokedPeers(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := ca.Generate(filepath.Join(dataDir, "ca")); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	dbPath := filepath.Join(dataDir, "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	if err := d.EnsureGroup(ctx, "web"); err != nil {
		t.Fatalf("EnsureGroup web: %v", err)
	}
	aliveKey := freshPeerKey(t)
	deadKey := freshPeerKey(t)
	if err := d.InsertPeer(ctx, "alive", 1, "fp-l", aliveKey, "alice", true, ""); err != nil {
		t.Fatalf("InsertPeer alive: %v", err)
	}
	if err := d.InsertPeer(ctx, "dead", 1, "fp-d", deadKey, "bob", true, ""); err != nil {
		t.Fatalf("InsertPeer dead: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "alive", []string{"web"}); err != nil {
		t.Fatalf("SetPeerGroups alive: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "dead", []string{"web"}); err != nil {
		t.Fatalf("SetPeerGroups dead: %v", err)
	}
	if err := d.SetPeerRevoked(ctx, "dead"); err != nil {
		t.Fatalf("SetPeerRevoked dead: %v", err)
	}
	d.Close()

	var dialedHosts []string
	fp := &fakePusher{}
	prev := groupDial
	groupDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		dialedHosts = append(dialedHosts, host)
		return fp, nil
	}
	t.Cleanup(func() { groupDial = prev })

	out, err := runGroupCmd(t, dataDir, dbPath, "delete", "web")
	if err != nil {
		t.Fatalf("delete: err=%v out=%s", err, out)
	}

	for _, h := range dialedHosts {
		if h == "dead" {
			t.Errorf("revoked peer 'dead' was dialed: %v", dialedHosts)
		}
	}
	if len(dialedHosts) != 1 || dialedHosts[0] != "alive" {
		t.Errorf("dialedHosts = %v, want [alive]", dialedHosts)
	}

	d, err = db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	got, err := d.GetPeerGroups(ctx, "alive")
	if err != nil {
		t.Fatalf("GetPeerGroups alive: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("alive groups = %v, want []", got)
	}
	if ok, _ := d.GroupExists(ctx, "web"); ok {
		t.Error("group 'web' should be deleted")
	}
}
