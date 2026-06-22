package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/sshpush"
)

func runPeerEdit(t *testing.T, dataDir, dbPath string, args ...string) (string, string, error) {
	t.Helper()
	cmd := NewRootCmd()
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	full := append([]string{"--db", dbPath, "--data-dir", dataDir}, args...)
	cmd.SetArgs(full)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), errBuf.String(), err
}

func setupPeerEditEnv(t *testing.T) (dataDir, dbPath string) {
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
	defer d.Close()
	ctx := context.Background()
	if _, err := EnsureInstanceKey(ctx, d); err != nil {
		t.Fatalf("EnsureInstanceKey: %v", err)
	}
	if err := d.InsertPeer(ctx, "alpha", 1, ssh.FingerprintSHA256(sshPub), pubAuth, "root", true, ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	if err := d.SetPeerReachable(ctx, "alpha", true); err != nil {
		t.Fatalf("SetPeerReachable: %v", err)
	}
	return dataDir, dbPath
}

func TestAddressAndMakeClientRegistered(t *testing.T) {
	have := map[string]bool{}
	for _, c := range NewRootCmd().Commands() {
		have[c.Name()] = true
	}
	for _, name := range []string{"address", "make-client"} {
		if !have[name] {
			t.Errorf("command %q not registered on root", name)
		}
	}
}

func TestAddressCmdArgs(t *testing.T) {
	dataDir, dbPath := setupPeerEditEnv(t)
	if _, _, err := runPeerEdit(t, dataDir, dbPath, "address", "alpha"); err == nil {
		t.Error("expected error with one arg")
	}
}

func TestAddressCmdSetsAndClears(t *testing.T) {
	dataDir, dbPath := setupPeerEditEnv(t)
	if _, stderr, err := runPeerEdit(t, dataDir, dbPath, "address", "alpha", "10.0.0.5"); err != nil {
		t.Fatalf("address set: %v stderr=%s", err, stderr)
	}
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	p, err := d.GetPeer(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.Address != "10.0.0.5" {
		t.Errorf("address = %q, want 10.0.0.5", p.Address)
	}
	d.Close()

	if _, _, err := runPeerEdit(t, dataDir, dbPath, "address", "alpha", ""); err != nil {
		t.Fatalf("address clear: %v", err)
	}
	d2, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d2.Close()
	p2, err := d2.GetPeer(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p2.Address != "" {
		t.Errorf("address = %q, want cleared", p2.Address)
	}
}

func TestMakeClientCmdArgs(t *testing.T) {
	dataDir, dbPath := setupPeerEditEnv(t)
	if _, _, err := runPeerEdit(t, dataDir, dbPath, "make-client"); err == nil {
		t.Error("expected error with no args")
	}
}

func TestMakeClientCmdInvokesOps(t *testing.T) {
	dataDir, dbPath := setupPeerEditEnv(t)

	mp := &mockPusher{readData: map[string][]byte{"/root/.ssh/authorized_keys": caLineFor(t, dataDir, "manager", "infra")}}
	prev := peerEditDial
	peerEditDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		return mp, nil
	}
	t.Cleanup(func() { peerEditDial = prev })

	if _, stderr, err := runPeerEdit(t, dataDir, dbPath, "make-client", "alpha"); err != nil {
		t.Fatalf("make-client: %v stderr=%s", err, stderr)
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	p, err := d.GetPeer(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.Inbound {
		t.Error("inbound must be false after make-client")
	}

	mp.mu.Lock()
	defer mp.mu.Unlock()
	wrote := false
	for _, c := range mp.calls {
		if c.op == "write" && c.path == "/root/.ssh/authorized_keys" {
			wrote = true
			if bytes.Contains(c.content, []byte("cert-authority")) {
				t.Errorf("pushed authorized_keys still has cert-authority:\n%s", c.content)
			}
		}
	}
	if !wrote {
		t.Errorf("authorized_keys not written; calls=%+v", mp.calls)
	}
}
