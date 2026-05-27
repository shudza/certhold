package cli

import (
	"bytes"
	"context"
	"io/fs"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
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

func (m *mockPusher) ReloadSSHD(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, mockCall{op: "reload"})
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

	fingerprint := ssh.FingerprintSHA256(sshPub)
	if err := d.InsertPeer(ctx, peerName, serial, fingerprint, pubAuth); err != nil {
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

func TestUpdateSuccess(t *testing.T) {
	dataDir, dbPath, oldSerial := setupUpdateEnv(t, "peer1", []string{"oldA"}, false)
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

	mp.mu.Lock()
	defer mp.mu.Unlock()
	if len(mp.calls) != 3 {
		t.Fatalf("calls = %d, want 3: %+v", len(mp.calls), mp.calls)
	}
	if mp.calls[0].op != "write" {
		t.Errorf("call[0] = %q, want write", mp.calls[0].op)
	}
	if mp.calls[0].path != "/etc/ssh/peer_ed25519-cert.pub" {
		t.Errorf("call[0].path = %q", mp.calls[0].path)
	}
	if mp.calls[0].mode != 0644 {
		t.Errorf("call[0].mode = %o, want 0644", mp.calls[0].mode)
	}
	if len(mp.calls[0].content) == 0 {
		t.Errorf("call[0].content is empty")
	}
	if mp.calls[1].op != "reload" {
		t.Errorf("call[1] = %q, want reload", mp.calls[1].op)
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

func setupUpdateUserPeer(t *testing.T, peerName, targetUser string) (dataDir, dbPath string) {
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
	if err := d.InsertPeerWithMode(context.Background(), peerName, 1, ssh.FingerprintSHA256(sshPub), pubAuth, db.ModeUser, targetUser, 1); err != nil {
		t.Fatalf("InsertPeerWithMode: %v", err)
	}
	return dataDir, dbPath
}

func TestUpdateUserMode_NoReload(t *testing.T) {
	dataDir, dbPath := setupUpdateUserPeer(t, "vmU", "alice")
	mp := withMockPusher(t)
	stdout, stderr, err := runUpdate(t, dataDir, dbPath, "vmU", "--groups", "infra")
	if err != nil {
		t.Fatalf("update user-mode: err=%v stderr=%s stdout=%s", err, stderr, stdout)
	}
	mp.mu.Lock()
	defer mp.mu.Unlock()
	wantPath := "/home/alice/.ssh/id_ed25519-cert.pub"
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

func setupUpdateV2Peer(t *testing.T, peerName, mode, targetUser string) (dataDir, dbPath, key string) {
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
	if err := d.InsertPeerWithMode(ctx, peerName, 1, ssh.FingerprintSHA256(sshPub), pubAuth, mode, targetUser, 2); err != nil {
		t.Fatalf("InsertPeerWithMode: %v", err)
	}
	d.Close()
	return dataDir, dbPath, key
}

func TestUpdateV2Root_NamespacedCert_NoReload(t *testing.T) {
	dataDir, dbPath, key := setupUpdateV2Peer(t, "vmV2", db.ModeRoot, "")
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
	dataDir, dbPath := setupUpdateUserPeer(t, "vmR", "root")
	mp := withMockPusher(t)
	if _, _, err := runUpdate(t, dataDir, dbPath, "vmR", "--groups", "infra"); err != nil {
		t.Fatalf("update: %v", err)
	}
	mp.mu.Lock()
	defer mp.mu.Unlock()
	for _, c := range mp.calls {
		if c.op == "write" && c.path != "/root/.ssh/id_ed25519-cert.pub" {
			t.Errorf("root user-mode write path = %q, want /root/.ssh/id_ed25519-cert.pub", c.path)
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
	if err := d.InsertPeer(ctx, peerName, serial, ssh.FingerprintSHA256(sshPub), pubAuth); err != nil {
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

func TestUpdateEncryptedCAViaEnv(t *testing.T) {
	const caPW = "ca-secret"
	dataDir, dbPath, oldSerial := setupUpdateEncryptedCAEnv(t, "peerEnc", []string{"oldA"}, caPW)
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
