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
	if err := d.InsertPeer(ctx, "peer1", 1, "fp", []byte("k"), "alice"); err != nil {
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
	if err := d.InsertPeer(context.Background(), "peer1", 1, "fp", []byte("k"), "alice"); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	key, _, _ := d.GetMeta(context.Background(), db.MetaInstanceKey)
	d.Close()

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
	if err := d.InsertPeer(context.Background(), peerName, 1, "fp", []byte("k"), targetUser); err != nil {
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
	if err := d.InsertPeer(ctx, "vmU", 1, "fp", []byte("k"), "alice"); err != nil {
		t.Fatalf("InsertPeer: %v", err)
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
	if err := d.InsertPeer(ctx, "vmRoot", 1, "fp", []byte("k"), "root"); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	if err := d.EnsureGroup(ctx, "infra"); err != nil {
		t.Fatalf("EnsureGroup: %v", err)
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
