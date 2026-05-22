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
	op       string
	path     string
	content  []byte
	mode     fs.FileMode
}

type mockPusher struct {
	mu     sync.Mutex
	calls  []mockCall
	closed bool
}

func (m *mockPusher) WriteFileAtomic(ctx context.Context, remotePath string, content []byte, mode fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, mockCall{op: "write", path: remotePath, content: append([]byte(nil), content...), mode: mode})
	return nil
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

func TestUpdateEmptyGroups(t *testing.T) {
	dataDir, dbPath, _ := setupUpdateEnv(t, "peer1", []string{"oldA"}, false)
	withMockPusher(t)
	if _, _, err := runUpdate(t, dataDir, dbPath, "peer1", "--groups", " , , "); err == nil {
		t.Fatal("expected error for empty groups")
	}
}
