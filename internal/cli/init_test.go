package cli_test

import (
	"bytes"
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shudza/certhold/internal/cli"
	"github.com/shudza/certhold/internal/db"
)

func TestInit_RootMode_HappyPath(t *testing.T) {
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "state.db")

	cmd := cli.NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", "manager-test", "--mode", "root", "--listen-ip", "127.0.0.1", "--no-prompt"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nout:\n%s", err, out.String())
	}

	caPriv := filepath.Join(dataDir, "ca", "ca")
	caPub := filepath.Join(dataDir, "ca", "ca.pub")
	for path, mode := range map[string]os.FileMode{caPriv: 0600, caPub: 0644} {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if st.Mode().Perm() != mode {
			t.Errorf("%s mode: got %o want %o", path, st.Mode().Perm(), mode)
		}
	}

	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("state.db: %v", err)
	}

	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()
	peers, err := database.ListPeers(context.Background())
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("peers count: got %d want 1", len(peers))
	}
	if peers[0].Name != "manager-test" {
		t.Errorf("peer name: got %q want %q", peers[0].Name, "manager-test")
	}
	if peers[0].Mode != db.ModeRoot {
		t.Errorf("peer mode: got %q want %q", peers[0].Mode, db.ModeRoot)
	}
	if peers[0].Serial == 0 {
		t.Errorf("peer serial is zero")
	}
	if !strings.HasPrefix(peers[0].Fingerprint, "SHA256:") {
		t.Errorf("peer fingerprint format: %q", peers[0].Fingerprint)
	}

	allowed, err := database.GetPeerAllowedGroups(context.Background(), "manager-test")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	if len(allowed) != 1 || allowed[0] != "manager" {
		t.Errorf("allowed groups: got %v want [manager]", allowed)
	}

	selfDir := filepath.Join(dataDir, "self")
	for _, rel := range []string{
		"etc/ssh/peer_ed25519",
		"etc/ssh/peer_ed25519-cert.pub",
		"etc/ssh/ca.pub",
		"etc/ssh/krl",
		"etc/ssh/auth_principals/root",
		"etc/ssh/ca_known_hosts",
		"etc/ssh/sshd_config_block.conf",
		"etc/ssh/ssh_config_block.conf",
	} {
		if _, err := os.Stat(filepath.Join(selfDir, rel)); err != nil {
			t.Errorf("missing self file %s: %v", rel, err)
		}
	}

	caKH, err := os.ReadFile(filepath.Join(selfDir, "etc/ssh/ca_known_hosts"))
	if err != nil {
		t.Fatalf("read ca_known_hosts: %v", err)
	}
	if !strings.HasPrefix(string(caKH), "@cert-authority * ssh-ed25519 ") {
		t.Errorf("ca_known_hosts: %q", caKH)
	}

	got := out.String()
	for _, want := range []string{"data-dir", "db", "ca fingerprint", "self files", "SHA256:"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary missing %q\nfull:\n%s", want, got)
		}
	}
}

func TestInit_UserMode_HappyPath(t *testing.T) {
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "state.db")

	cmd := cli.NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", "manager-test", "--user", "alice", "--listen-ip", "127.0.0.1", "--no-prompt"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nout:\n%s", err, out.String())
	}

	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()
	p, err := database.GetPeer(context.Background(), "manager-test")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.Mode != db.ModeUser || p.TargetUser != "alice" {
		t.Errorf("got mode=%q tu=%q, want user/alice", p.Mode, p.TargetUser)
	}
	base := filepath.Join(dataDir, "self", "home", "alice", ".ssh")
	for name, mode := range map[string]os.FileMode{
		"id_ed25519":          0600,
		"id_ed25519-cert.pub": 0644,
		"authorized_keys":     0644,
		"known_hosts":         0644,
		"config":              0644,
	} {
		st, err := os.Stat(filepath.Join(base, name))
		if err != nil {
			t.Errorf("missing %s: %v", name, err)
			continue
		}
		if st.Mode().Perm() != mode {
			t.Errorf("%s mode: got %o want %o", name, st.Mode().Perm(), mode)
		}
	}
	ak, err := os.ReadFile(filepath.Join(base, "authorized_keys"))
	if err != nil {
		t.Fatalf("read authorized_keys: %v", err)
	}
	if !strings.HasPrefix(string(ak), `cert-authority,principals="manager" `) {
		t.Errorf("authorized_keys = %q, expected to start with principals=\"manager\"", ak)
	}
}

func TestInit_UserMode_DefaultsToCurrentUser(t *testing.T) {
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "state.db")

	cmd := cli.NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", "manager-test", "--listen-ip", "127.0.0.1", "--no-prompt"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nout:\n%s", err, out.String())
	}

	cur, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	want := cur.Username

	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()
	p, err := database.GetPeer(context.Background(), "manager-test")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.Mode != db.ModeUser || p.TargetUser != want {
		t.Errorf("got mode=%q tu=%q, want user/%s", p.Mode, p.TargetUser, want)
	}

	homeRel := "home/" + want
	if want == "root" {
		homeRel = "root"
	}
	wantSSH := filepath.Join(dataDir, "self", homeRel, ".ssh", "id_ed25519")
	if _, err := os.Stat(wantSSH); err != nil {
		t.Errorf("expected self file at %s: %v", wantSSH, err)
	}
}

func TestInit_PersistsBaseURL(t *testing.T) {
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "state.db")

	cmd := cli.NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--mode", "root", "--listen-ip", "10.0.0.5", "--port", "9000", "--no-prompt"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nout:\n%s", err, out.String())
	}

	raw, err := os.ReadFile(filepath.Join(dataDir, "base_url"))
	if err != nil {
		t.Fatalf("read base_url: %v", err)
	}
	if string(raw) != "https://10.0.0.5:9000\n" {
		t.Errorf("base_url = %q, want %q", raw, "https://10.0.0.5:9000\n")
	}
	if !strings.Contains(out.String(), "base url:       https://10.0.0.5:9000") {
		t.Errorf("summary missing base url line:\n%s", out.String())
	}
}

func TestInit_InvalidListenIP(t *testing.T) {
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "state.db")

	cmd := cli.NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--mode", "root", "--listen-ip", "not-an-ip", "--no-prompt"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(dbPath); err == nil {
		t.Errorf("db should not be created on invalid listen-ip")
	}
}

func TestInit_Idempotency(t *testing.T) {
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "state.db")

	run := func() error {
		cmd := cli.NewRootCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", "manager-test", "--mode", "root", "--listen-ip", "127.0.0.1", "--no-prompt"})
		return cmd.Execute()
	}

	if err := run(); err != nil {
		t.Fatalf("first init: %v", err)
	}
	if err := run(); err == nil {
		t.Fatalf("second init should fail")
	}
}
