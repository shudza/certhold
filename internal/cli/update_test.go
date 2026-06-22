package cli

import (
	"bytes"
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/peerfiles"
	"github.com/shudza/certhold/internal/sshpush"
)

type mockCall struct {
	op      string
	path    string
	content []byte
	mode    fs.FileMode
}

type mockPusher struct {
	mu       sync.Mutex
	calls    []mockCall
	closed   bool
	readData map[string][]byte
}

func (m *mockPusher) WriteFileAtomic(ctx context.Context, remotePath string, content []byte, mode fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, mockCall{op: "write", path: remotePath, content: append([]byte(nil), content...), mode: mode})
	return nil
}

func (m *mockPusher) ReadFile(ctx context.Context, remotePath string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, mockCall{op: "read", path: remotePath})
	if data, ok := m.readData[remotePath]; ok {
		return append([]byte(nil), data...), nil
	}
	return nil, nil
}

func (m *mockPusher) SpliceConfigBlock(ctx context.Context, configPath, instanceKey, block string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, mockCall{op: "splice", path: configPath, content: []byte(block)})
	return nil
}

func (m *mockPusher) ReloadSSHD(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, mockCall{op: "reload"})
	return nil
}

func (m *mockPusher) ClearPeer(ctx context.Context, paths peerfiles.RemotePaths, instanceKey string, caPubKey ssh.PublicKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, mockCall{op: "clear", path: paths.ConfigTarget})
	return nil
}

func (m *mockPusher) VerifyHealth(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, mockCall{op: "verify"})
	return nil
}

func (m *mockPusher) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func setupUpdateEnv(t *testing.T, peerName string, initialGroups []string, revoked bool) (dataDir, dbPath string, oldSerial uint64) {
	t.Helper()
	dataDir = t.TempDir()
	caObj, err := ca.Generate(filepath.Join(dataDir, "ca"))
	if err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	_, pubAuth, sshPub, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	certBytes, serial, err := caObj.SignCert(ca.SignOptions{
		Pubkey:     sshPub,
		KeyID:      peerName,
		Principals: append([]string{peerName}, initialGroups...),
	})
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	_ = certBytes

	dbPath = filepath.Join(dataDir, "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	ctx := context.Background()

	if _, err := EnsureInstanceKey(ctx, d); err != nil {
		t.Fatalf("EnsureInstanceKey: %v", err)
	}
	fingerprint := ssh.FingerprintSHA256(sshPub)
	if err := d.InsertPeer(ctx, peerName, serial, fingerprint, pubAuth, "root", true, ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	for _, g := range initialGroups {
		if err := d.EnsureGroup(ctx, g); err != nil {
			t.Fatalf("EnsureGroup: %v", err)
		}
	}
	if len(initialGroups) > 0 {
		if err := d.SetPeerGroups(ctx, peerName, initialGroups); err != nil {
			t.Fatalf("SetPeerGroups: %v", err)
		}
	}
	if revoked {
		if err := d.SetPeerRevoked(ctx, peerName); err != nil {
			t.Fatalf("SetPeerRevoked: %v", err)
		}
	}
	return dataDir, dbPath, serial
}

func runUpdate(t *testing.T, dataDir, dbPath string, args ...string) (string, string, error) {
	t.Helper()
	cmd := NewRootCmd()
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	full := append([]string{"--db", dbPath, "--data-dir", dataDir, "update"}, args...)
	cmd.SetArgs(full)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), errBuf.String(), err
}

func withMockPusher(t *testing.T) *mockPusher {
	t.Helper()
	mp := &mockPusher{}
	prev := dialFn
	dialFn = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		return mp, nil
	}
	t.Cleanup(func() { dialFn = prev })
	return mp
}

// withMockPusherCapturingHost installs a dial stub that records the host argument
// so tests can assert the dial target (address vs name vs --host).
func withMockPusherCapturingHost(t *testing.T, gotHost *string) *mockPusher {
	t.Helper()
	mp := &mockPusher{}
	prev := dialFn
	dialFn = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		*gotHost = host
		return mp, nil
	}
	t.Cleanup(func() { dialFn = prev })
	return mp
}

// withMockPusherCapturingUser installs a dial stub that records the SSH user
// the push authenticates as, so tests can assert update targets the peer's
// owning user (not an unconditional root).
func withMockPusherCapturingUser(t *testing.T, gotUser *string) *mockPusher {
	t.Helper()
	mp := &mockPusher{}
	prev := dialFn
	dialFn = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		*gotUser = opts.User
		return mp, nil
	}
	t.Cleanup(func() { dialFn = prev })
	return mp
}

func TestUpdateDialsTargetUserForUserModePeer(t *testing.T) {
	dataDir := t.TempDir()
	caObj, err := ca.Generate(filepath.Join(dataDir, "ca"))
	if err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	_, pubAuth, sshPub, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	_, serial, err := caObj.SignCert(ca.SignOptions{Pubkey: sshPub, KeyID: "web01", Principals: []string{"web01", "web"}})
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	dbPath := filepath.Join(dataDir, "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	if err := d.InsertPeer(ctx, "web01", serial, ssh.FingerprintSHA256(sshPub), pubAuth, "deploy", true, ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	if err := d.EnsureGroup(ctx, "web"); err != nil {
		t.Fatalf("EnsureGroup: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "web01", []string{"web"}); err != nil {
		t.Fatalf("SetPeerGroups: %v", err)
	}
	d.Close()

	var gotUser string
	withMockPusherCapturingUser(t, &gotUser)
	if _, stderr, err := runUpdate(t, dataDir, dbPath, "web01", "--groups", "web"); err != nil {
		t.Fatalf("update: err=%v stderr=%s", err, stderr)
	}
	if gotUser != "deploy" {
		t.Errorf("dialed user = %q, want deploy (user-mode peer's owning user)", gotUser)
	}
}

func TestUpdateDialsRootForRootTargetPeer(t *testing.T) {
	dataDir, dbPath, _ := setupUpdateEnv(t, "peer1", []string{"oldA"}, false)
	preCreateGroups(t, dbPath, "newA")
	var gotUser string
	withMockPusherCapturingUser(t, &gotUser)
	if _, stderr, err := runUpdate(t, dataDir, dbPath, "peer1", "--groups", "newA"); err != nil {
		t.Fatalf("update: err=%v stderr=%s", err, stderr)
	}
	if gotUser != "root" {
		t.Errorf("dialed user = %q, want root (target_user=root peer)", gotUser)
	}
}

func TestUpdateDialsAddressWhenNoHostFlag(t *testing.T) {
	dataDir, dbPath, _ := setupUpdateEnv(t, "peer1", []string{"oldA"}, false)
	preCreateGroups(t, dbPath, "newA")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := d.SetPeerAddress(context.Background(), "peer1", "10.0.0.5"); err != nil {
		t.Fatalf("SetPeerAddress: %v", err)
	}
	d.Close()

	var gotHost string
	withMockPusherCapturingHost(t, &gotHost)
	if _, stderr, err := runUpdate(t, dataDir, dbPath, "peer1", "--groups", "newA"); err != nil {
		t.Fatalf("update: err=%v stderr=%s", err, stderr)
	}
	if gotHost != "10.0.0.5" {
		t.Errorf("dialed host = %q, want 10.0.0.5 (the peer address)", gotHost)
	}
}

func TestUpdateHostFlagBeatsAddress(t *testing.T) {
	dataDir, dbPath, _ := setupUpdateEnv(t, "peer1", []string{"oldA"}, false)
	preCreateGroups(t, dbPath, "newA")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := d.SetPeerAddress(context.Background(), "peer1", "10.0.0.5"); err != nil {
		t.Fatalf("SetPeerAddress: %v", err)
	}
	d.Close()

	var gotHost string
	withMockPusherCapturingHost(t, &gotHost)
	if _, stderr, err := runUpdate(t, dataDir, dbPath, "peer1", "--groups", "newA", "--host", "explicit.host"); err != nil {
		t.Fatalf("update: err=%v stderr=%s", err, stderr)
	}
	if gotHost != "explicit.host" {
		t.Errorf("dialed host = %q, want explicit.host (--host overrides address)", gotHost)
	}
}

func TestUpdateDialsNameWhenNoAddress(t *testing.T) {
	dataDir, dbPath, _ := setupUpdateEnv(t, "peer1", []string{"oldA"}, false)
	preCreateGroups(t, dbPath, "newA")
	var gotHost string
	withMockPusherCapturingHost(t, &gotHost)
	if _, stderr, err := runUpdate(t, dataDir, dbPath, "peer1", "--groups", "newA"); err != nil {
		t.Fatalf("update: err=%v stderr=%s", err, stderr)
	}
	if gotHost != "peer1" {
		t.Errorf("dialed host = %q, want peer1 (the name, no address set)", gotHost)
	}
}

func TestUpdateSuccess(t *testing.T) {
	dataDir, dbPath, oldSerial := setupUpdateEnv(t, "peer1", []string{"oldA"}, false)
	preCreateGroups(t, dbPath, "newA", "newB")
	mp := withMockPusher(t)

	stdout, stderr, err := runUpdate(t, dataDir, dbPath, "peer1", "--groups", "newA,newB")
	if err != nil {
		t.Fatalf("update: err=%v stderr=%s stdout=%s", err, stderr, stdout)
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d.Close()
	peer, err := d.GetPeer(context.Background(), "peer1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if peer.Serial == oldSerial {
		t.Errorf("serial unchanged: %d", peer.Serial)
	}
	groups, err := d.GetPeerGroups(context.Background(), "peer1")
	if err != nil {
		t.Fatalf("GetPeerGroups: %v", err)
	}
	if got, want := len(groups), 2; got != want {
		t.Fatalf("groups len=%d want %d (%v)", got, want, groups)
	}
	if groups[0] != "newA" || groups[1] != "newB" {
		t.Errorf("groups = %v, want [newA newB]", groups)
	}

	key := instanceKeyFromDBPkg(t, dbPath)
	mp.mu.Lock()
	defer mp.mu.Unlock()
	// v2 peer: a namespaced cert write, the config splice, then verify — no
	// sshd reload.
	if len(mp.calls) != 3 {
		t.Fatalf("calls = %d, want 3: %+v", len(mp.calls), mp.calls)
	}
	if mp.calls[0].op != "write" {
		t.Errorf("call[0] = %q, want write", mp.calls[0].op)
	}
	if mp.calls[0].path != "/root/.ssh/id_ed25519_"+key+"-cert.pub" {
		t.Errorf("call[0].path = %q, want /root/.ssh/id_ed25519_%s-cert.pub", mp.calls[0].path, key)
	}
	if mp.calls[0].mode != 0644 {
		t.Errorf("call[0].mode = %o, want 0644", mp.calls[0].mode)
	}
	if len(mp.calls[0].content) == 0 {
		t.Errorf("call[0].content is empty")
	}
	for _, c := range mp.calls {
		if c.op == "reload" {
			t.Errorf("v2 update must NOT reload sshd; calls=%+v", mp.calls)
		}
	}
	if mp.calls[1].op != "splice" || mp.calls[1].path != "/root/.ssh/config" {
		t.Errorf("call[1] = %q %q, want splice /root/.ssh/config", mp.calls[1].op, mp.calls[1].path)
	}
	if mp.calls[2].op != "verify" {
		t.Errorf("call[2] = %q, want verify", mp.calls[2].op)
	}
	if !mp.closed {
		t.Errorf("pusher was not closed")
	}
}

func TestUpdateUnknownPeer(t *testing.T) {
	dataDir, dbPath, _ := setupUpdateEnv(t, "peer1", []string{"oldA"}, false)
	withMockPusher(t)
	if _, _, err := runUpdate(t, dataDir, dbPath, "ghost", "--groups", "x"); err == nil {
		t.Fatal("expected error for unknown peer")
	}
}

func TestUpdateRevokedPeer(t *testing.T) {
	dataDir, dbPath, _ := setupUpdateEnv(t, "peer1", []string{"oldA"}, true)
	withMockPusher(t)
	if _, _, err := runUpdate(t, dataDir, dbPath, "peer1", "--groups", "x"); err == nil {
		t.Fatal("expected error for revoked peer")
	}
}

func setupUpdateUserPeer(t *testing.T, peerName, targetUser string) (dataDir, dbPath, key string) {
	t.Helper()
	dataDir = t.TempDir()
	caObj, err := ca.Generate(filepath.Join(dataDir, "ca"))
	if err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	_ = caObj
	_, pubAuth, sshPub, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	dbPath = filepath.Join(dataDir, "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	ctx := context.Background()
	key, err = EnsureInstanceKey(ctx, d)
	if err != nil {
		t.Fatalf("EnsureInstanceKey: %v", err)
	}
	if err := d.InsertPeer(ctx, peerName, 1, ssh.FingerprintSHA256(sshPub), pubAuth, targetUser, true, ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	return dataDir, dbPath, key
}

func TestUpdateUserMode_NoReload(t *testing.T) {
	dataDir, dbPath, key := setupUpdateUserPeer(t, "vmU", "alice")
	preCreateGroups(t, dbPath, "infra")
	mp := withMockPusher(t)
	stdout, stderr, err := runUpdate(t, dataDir, dbPath, "vmU", "--groups", "infra")
	if err != nil {
		t.Fatalf("update user-mode: err=%v stderr=%s stdout=%s", err, stderr, stdout)
	}
	mp.mu.Lock()
	defer mp.mu.Unlock()
	wantPath := "/home/alice/.ssh/id_ed25519_" + key + "-cert.pub"
	gotPath := ""
	reloaded := false
	for _, c := range mp.calls {
		if c.op == "write" {
			gotPath = c.path
		}
		if c.op == "reload" {
			reloaded = true
		}
	}
	if gotPath != wantPath {
		t.Errorf("write path = %q, want %q", gotPath, wantPath)
	}
	if reloaded {
		t.Errorf("user-mode update should NOT call ReloadSSHD; calls=%+v", mp.calls)
	}
}

func setupUpdateV2Peer(t *testing.T, peerName, targetUser string) (dataDir, dbPath, key string) {
	t.Helper()
	dataDir = t.TempDir()
	if _, err := ca.Generate(filepath.Join(dataDir, "ca")); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	_, pubAuth, sshPub, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	dbPath = filepath.Join(dataDir, "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	key, err = EnsureInstanceKey(ctx, d)
	if err != nil {
		t.Fatalf("EnsureInstanceKey: %v", err)
	}
	if err := d.InsertPeer(ctx, peerName, 1, ssh.FingerprintSHA256(sshPub), pubAuth, targetUser, true, ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	d.Close()
	return dataDir, dbPath, key
}

func TestUpdateV2Root_NamespacedCert_NoReload(t *testing.T) {
	dataDir, dbPath, key := setupUpdateV2Peer(t, "vmV2", "root")
	preCreateGroups(t, dbPath, "infra")
	mp := withMockPusher(t)
	if _, _, err := runUpdate(t, dataDir, dbPath, "vmV2", "--groups", "infra"); err != nil {
		t.Fatalf("update v2 root: %v", err)
	}
	mp.mu.Lock()
	defer mp.mu.Unlock()
	wantPath := "/root/.ssh/id_ed25519_" + key + "-cert.pub"
	gotPath := ""
	reloaded := false
	for _, c := range mp.calls {
		if c.op == "write" {
			gotPath = c.path
		}
		if c.op == "reload" {
			reloaded = true
		}
	}
	if gotPath != wantPath {
		t.Errorf("v2 root write path = %q, want %q", gotPath, wantPath)
	}
	if reloaded {
		t.Errorf("v2 update must NOT reload sshd; calls=%+v", mp.calls)
	}
}

func TestUpdateUserMode_RootUserHomeIsSlashRoot(t *testing.T) {
	dataDir, dbPath, key := setupUpdateUserPeer(t, "vmR", "root")
	preCreateGroups(t, dbPath, "infra")
	mp := withMockPusher(t)
	if _, _, err := runUpdate(t, dataDir, dbPath, "vmR", "--groups", "infra"); err != nil {
		t.Fatalf("update: %v", err)
	}
	mp.mu.Lock()
	defer mp.mu.Unlock()
	wantPath := "/root/.ssh/id_ed25519_" + key + "-cert.pub"
	for _, c := range mp.calls {
		if c.op == "write" && c.path != wantPath {
			t.Errorf("root user-mode write path = %q, want %q", c.path, wantPath)
		}
	}
}

func setupUpdateEncryptedCAEnv(t *testing.T, peerName string, initialGroups []string, caPW string) (dataDir, dbPath string, oldSerial uint64) {
	t.Helper()
	dataDir = t.TempDir()
	caObj, err := ca.GenerateWithPassphrase(filepath.Join(dataDir, "ca"), []byte(caPW))
	if err != nil {
		t.Fatalf("ca.GenerateWithPassphrase: %v", err)
	}
	_, pubAuth, sshPub, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	_, serial, err := caObj.SignCert(ca.SignOptions{
		Pubkey:     sshPub,
		KeyID:      peerName,
		Principals: append([]string{peerName}, initialGroups...),
	})
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}

	dbPath = filepath.Join(dataDir, "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	ctx := context.Background()
	if _, err := EnsureInstanceKey(ctx, d); err != nil {
		t.Fatalf("EnsureInstanceKey: %v", err)
	}
	if err := d.InsertPeer(ctx, peerName, serial, ssh.FingerprintSHA256(sshPub), pubAuth, "root", true, ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	for _, g := range initialGroups {
		if err := d.EnsureGroup(ctx, g); err != nil {
			t.Fatalf("EnsureGroup: %v", err)
		}
	}
	if len(initialGroups) > 0 {
		if err := d.SetPeerGroups(ctx, peerName, initialGroups); err != nil {
			t.Fatalf("SetPeerGroups: %v", err)
		}
	}
	return dataDir, dbPath, serial
}

// TestUpdate_FailsWhenGroupDoesNotExist verifies update errors when --groups
// references a missing group and leaves the peer's existing groups untouched.
func TestUpdate_FailsWhenGroupDoesNotExist(t *testing.T) {
	dataDir, dbPath, _ := setupUpdateEnv(t, "alpha", []string{"oldA"}, false)
	withMockPusher(t)

	_, stderr, err := runUpdate(t, dataDir, dbPath, "alpha", "--groups", "newgrp")
	if err == nil {
		t.Fatal("expected update to fail for nonexistent group, got nil")
	}
	msg := err.Error() + stderr
	if !strings.Contains(msg, "newgrp") {
		t.Errorf("error %q does not mention group name", msg)
	}
	if !strings.Contains(msg, "group create") {
		t.Errorf("error %q does not guide user to `group create`", msg)
	}

	d, dbErr := db.Open(dbPath)
	if dbErr != nil {
		t.Fatalf("reopen db: %v", dbErr)
	}
	defer d.Close()
	groups, gerr := d.GetPeerGroups(context.Background(), "alpha")
	if gerr != nil {
		t.Fatalf("GetPeerGroups: %v", gerr)
	}
	if len(groups) != 1 || groups[0] != "oldA" {
		t.Errorf("peer groups = %v, want [oldA] (unchanged)", groups)
	}
}

func TestUpdateEncryptedCAViaEnv(t *testing.T) {
	const caPW = "ca-secret"
	dataDir, dbPath, oldSerial := setupUpdateEncryptedCAEnv(t, "peerEnc", []string{"oldA"}, caPW)
	preCreateGroups(t, dbPath, "newA", "newB")
	mp := withMockPusher(t)

	t.Setenv("CERTHOLD_CA_PASSPHRASE", caPW)
	t.Setenv("CERTHOLD_PEER_PASSPHRASE", "peer-secret")

	stdout, stderr, err := runUpdate(t, dataDir, dbPath, "peerEnc", "--groups", "newA,newB")
	if err != nil {
		t.Fatalf("update against encrypted CA: err=%v stderr=%s stdout=%s", err, stderr, stdout)
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d.Close()
	peer, err := d.GetPeer(context.Background(), "peerEnc")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if peer.Serial == oldSerial {
		t.Errorf("serial unchanged after encrypted-CA update: %d", peer.Serial)
	}

	mp.mu.Lock()
	defer mp.mu.Unlock()
	if len(mp.calls) == 0 || mp.calls[0].op != "write" {
		t.Fatalf("expected a cert write after encrypted-CA update; calls=%+v", mp.calls)
	}
}

func TestUpdateEncryptedCAWrongPassphraseFails(t *testing.T) {
	dataDir, dbPath, _ := setupUpdateEncryptedCAEnv(t, "peerEnc", []string{"oldA"}, "right")
	withMockPusher(t)
	t.Setenv("CERTHOLD_CA_PASSPHRASE", "wrong")
	if _, _, err := runUpdate(t, dataDir, dbPath, "peerEnc", "--groups", "x"); err == nil {
		t.Fatal("update with wrong CA passphrase: want error, got nil")
	}
}

func TestUpdateEmptyGroups(t *testing.T) {
	dataDir, dbPath, _ := setupUpdateEnv(t, "peer1", []string{"oldA"}, false)
	withMockPusher(t)
	if _, _, err := runUpdate(t, dataDir, dbPath, "peer1", "--groups", " , , "); err == nil {
		t.Fatal("expected error for empty groups")
	}
}

func TestUpdateClientPeer_SkipsDialNoticeAndPersistsCert(t *testing.T) {
	dataDir := t.TempDir()
	caObj, err := ca.Generate(filepath.Join(dataDir, "ca"))
	if err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	_, pubAuth, sshPub, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	dbPath := filepath.Join(dataDir, "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	if _, err := EnsureInstanceKey(ctx, d); err != nil {
		t.Fatalf("EnsureInstanceKey: %v", err)
	}
	if err := d.InsertPeer(ctx, "laptop", 1, ssh.FingerprintSHA256(sshPub), pubAuth, "alice", false, "tok-laptop"); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	d.Close()
	preCreateGroups(t, dbPath, "infra")

	dialCount := 0
	prev := dialFn
	dialFn = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		dialCount++
		return &mockPusher{}, nil
	}
	t.Cleanup(func() { dialFn = prev })

	stdout, stderr, err := runUpdate(t, dataDir, dbPath, "laptop", "--groups", "infra")
	if err != nil {
		t.Fatalf("update client peer: err=%v stderr=%s stdout=%s", err, stderr, stdout)
	}
	if dialCount != 0 {
		t.Errorf("client peer was dialed %d times, want 0", dialCount)
	}
	wantNotice := "client peer laptop: changes pending until 'certhold-cli refresh' runs on it"
	if !strings.Contains(stdout, wantNotice) {
		t.Errorf("stdout missing notice %q:\n%s", wantNotice, stdout)
	}

	d2, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d2.Close()
	p, err := d2.GetPeer(ctx, "laptop")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if len(p.Cert) == 0 {
		t.Fatal("client peer cert not stored in db")
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(p.Cert)
	if err != nil {
		t.Fatalf("parse stored cert: %v", err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		t.Fatalf("stored cert is %T, want *ssh.Certificate", pk)
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey(caObj.PublicKeyAuthorizedKey())
	if err != nil {
		t.Fatalf("parse ca pub: %v", err)
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) {
		t.Error("stored cert not signed by the CA")
	}
	if cert.Serial != p.Serial {
		t.Errorf("stored cert serial %d != peer cert_serial %d", cert.Serial, p.Serial)
	}
	groups, err := d2.GetPeerGroups(ctx, "laptop")
	if err != nil {
		t.Fatalf("GetPeerGroups: %v", err)
	}
	if len(groups) != 1 || groups[0] != "infra" {
		t.Errorf("groups = %v, want [infra] (DB-side change must still land)", groups)
	}
}

func TestUpdateInboundPeer_SplicesConfigWithReachableHosts(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := ca.Generate(filepath.Join(dataDir, "ca")); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	_, pubAuth, sshPub, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	dbPath := filepath.Join(dataDir, "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	key, err := EnsureInstanceKey(ctx, d)
	if err != nil {
		t.Fatalf("EnsureInstanceKey: %v", err)
	}
	if err := d.InsertPeer(ctx, "web01", 1, ssh.FingerprintSHA256(sshPub), pubAuth, "alice", true, ""); err != nil {
		t.Fatalf("InsertPeer web01: %v", err)
	}
	if err := d.InsertPeer(ctx, "db01", 1, "fp-db", []byte("k"), "dbadmin", true, ""); err != nil {
		t.Fatalf("InsertPeer db01: %v", err)
	}
	if err := d.EnsureGroup(ctx, "infra"); err != nil {
		t.Fatalf("EnsureGroup: %v", err)
	}
	if err := d.SetPeerAddress(ctx, "db01", "10.0.0.7"); err != nil {
		t.Fatalf("SetPeerAddress: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "db01", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups: %v", err)
	}
	d.Close()

	mp := withMockPusher(t)
	if _, stderr, err := runUpdate(t, dataDir, dbPath, "web01", "--groups", "infra"); err != nil {
		t.Fatalf("update: err=%v stderr=%s", err, stderr)
	}

	mp.mu.Lock()
	defer mp.mu.Unlock()
	var spliceCall *mockCall
	for i := range mp.calls {
		if mp.calls[i].op == "splice" {
			spliceCall = &mp.calls[i]
		}
	}
	if spliceCall == nil {
		t.Fatalf("no splice call; calls=%+v", mp.calls)
	}
	if spliceCall.path != "/home/alice/.ssh/config" {
		t.Errorf("splice path = %q, want /home/alice/.ssh/config", spliceCall.path)
	}
	block := string(spliceCall.content)
	for _, want := range []string{
		"# BEGIN certhold " + key,
		"Host db01\n",
		"    HostName 10.0.0.7\n",
		"    User dbadmin\n",
		"# END certhold " + key,
	} {
		if !strings.Contains(block, want) {
			t.Errorf("splice block missing %q:\n%s", want, block)
		}
	}
}
