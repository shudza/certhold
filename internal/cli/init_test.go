package cli_test

import (
	"bytes"
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/cli"
	"github.com/shudza/certhold/internal/db"
)

func is16Hex(s string) bool {
	if len(s) != 16 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// setInitPassphrases injects the CA + manager passphrases via env so init's
// default (passphrase-protected) path never blocks on a tty in tests.
func setInitPassphrases(t *testing.T) {
	t.Helper()
	t.Setenv("CERTHOLD_CA_PASSPHRASE", "test-ca-pw")
	t.Setenv("CERTHOLD_PEER_PASSPHRASE", "test-peer-pw")
}

func TestInit_RootUser_HappyPath(t *testing.T) {
	setInitPassphrases(t)
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "state.db")

	cmd := cli.NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", "manager-test", "--user", "root", "--listen-ip", "127.0.0.1", "--no-prompt"})
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
	if peers[0].TargetUser != "root" {
		t.Errorf("peer target user: got %q want root", peers[0].TargetUser)
	}
	if peers[0].Serial == 0 {
		t.Errorf("peer serial is zero")
	}
	if !strings.HasPrefix(peers[0].Fingerprint, "SHA256:") {
		t.Errorf("peer fingerprint format: %q", peers[0].Fingerprint)
	}

	// init backfills/sets a 16-hex instance key.
	key, ok, err := database.GetMeta(context.Background(), db.MetaInstanceKey)
	if err != nil || !ok {
		t.Fatalf("GetMeta instance_key: ok=%v err=%v", ok, err)
	}
	if !is16Hex(key) {
		t.Errorf("instance_key %q is not 16 lowercase hex chars", key)
	}

	allowed, err := database.GetPeerAllowedGroups(context.Background(), "manager-test")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	if len(allowed) != 1 || allowed[0] != "manager" {
		t.Errorf("allowed groups: got %v want [manager]", allowed)
	}

	// init must seed an active CA version (version 1) and bump fleet_rev, so
	// the TUI/serve "is this DB initialized?" gate (ActiveCAVersion) passes.
	if ver, err := database.ActiveCAVersion(context.Background()); err != nil || ver != 1 {
		t.Errorf("active ca version after init = %d (err=%v), want 1", ver, err)
	}
	if rev, err := database.FleetRev(context.Background()); err != nil || rev != 1 {
		t.Errorf("fleet_rev after init = %d (err=%v), want 1", rev, err)
	}

	// v2 root self files live under self/root/.ssh/ with namespaced identity.
	selfDir := filepath.Join(dataDir, "self")
	base := filepath.Join(selfDir, "root", ".ssh")
	for _, rel := range []string{
		"id_ed25519_" + key,
		"id_ed25519_" + key + "-cert.pub",
		"authorized_keys",
		"config",
	} {
		if _, err := os.Stat(filepath.Join(base, rel)); err != nil {
			t.Errorf("missing self file %s: %v", rel, err)
		}
	}
	// No legacy host-level self files under v2.
	if _, err := os.Stat(filepath.Join(selfDir, "etc", "ssh", "peer_ed25519")); err == nil {
		t.Errorf("v2 init must not write legacy self files under etc/ssh")
	}
	cfg, err := os.ReadFile(filepath.Join(base, "config"))
	if err != nil {
		t.Fatalf("read self config: %v", err)
	}
	if !strings.Contains(string(cfg), "# BEGIN certhold "+key+" v2") {
		t.Errorf("self config missing keyed v2 sentinel: %q", cfg)
	}

	got := out.String()
	for _, want := range []string{"data-dir", "db", "ca fingerprint", "self files", "SHA256:"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary missing %q\nfull:\n%s", want, got)
		}
	}
}

func TestInit_NoPassphrase_WritesPlaintext(t *testing.T) {
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "state.db")

	cmd := cli.NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader("yes\n"))
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", "m", "--user", "root", "--listen-ip", "127.0.0.1", "--no-prompt", "--no-passphrase"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nout:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "WARNING: --no-passphrase") {
		t.Errorf("banner not printed:\n%s", out.String())
	}

	// The CA key must be plaintext-parseable (no passphrase).
	keyBytes, err := os.ReadFile(filepath.Join(dataDir, "ca", "ca"))
	if err != nil {
		t.Fatalf("read ca key: %v", err)
	}
	if _, err := ssh.ParsePrivateKey(keyBytes); err != nil {
		t.Errorf("ca key should be plaintext-parseable: %v", err)
	}
}

func TestInit_NoPassphrase_RequiresYes(t *testing.T) {
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "state.db")

	cmd := cli.NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader("no\n"))
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", "m", "--user", "root", "--listen-ip", "127.0.0.1", "--no-prompt", "--no-passphrase"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when --no-passphrase not confirmed")
	}
}

func TestInit_UserMode_HappyPath(t *testing.T) {
	setInitPassphrases(t)
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
	if p.TargetUser != "alice" {
		t.Errorf("got tu=%q, want alice", p.TargetUser)
	}
	key, ok, err := database.GetMeta(context.Background(), db.MetaInstanceKey)
	if err != nil || !ok {
		t.Fatalf("GetMeta instance_key: ok=%v err=%v", ok, err)
	}
	base := filepath.Join(dataDir, "self", "home", "alice", ".ssh")
	for name, mode := range map[string]os.FileMode{
		"id_ed25519_" + key:               0600,
		"id_ed25519_" + key + "-cert.pub": 0644,
		"authorized_keys":                 0644,
		"config":                          0644,
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
	setInitPassphrases(t)
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
	if p.TargetUser != want {
		t.Errorf("got tu=%q, want %s", p.TargetUser, want)
	}

	key, ok, err := database.GetMeta(context.Background(), db.MetaInstanceKey)
	if err != nil || !ok {
		t.Fatalf("GetMeta instance_key: ok=%v err=%v", ok, err)
	}
	homeRel := "home/" + want
	if want == "root" {
		homeRel = "root"
	}
	wantSSH := filepath.Join(dataDir, "self", homeRel, ".ssh", "id_ed25519_"+key)
	if _, err := os.Stat(wantSSH); err != nil {
		t.Errorf("expected self file at %s: %v", wantSSH, err)
	}
}

func TestInit_PersistsBaseURL(t *testing.T) {
	setInitPassphrases(t)
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "state.db")

	cmd := cli.NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--user", "root", "--listen-ip", "10.0.0.5", "--port", "9000", "--no-prompt"})
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
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--user", "root", "--listen-ip", "not-an-ip", "--no-prompt"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(dbPath); err == nil {
		t.Errorf("db should not be created on invalid listen-ip")
	}
}

func TestInit_Idempotency(t *testing.T) {
	setInitPassphrases(t)
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "state.db")

	run := func() error {
		cmd := cli.NewRootCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", "manager-test", "--user", "root", "--listen-ip", "127.0.0.1", "--no-prompt"})
		return cmd.Execute()
	}

	if err := run(); err != nil {
		t.Fatalf("first init: %v", err)
	}
	if err := run(); err == nil {
		t.Fatalf("second init should fail")
	}
}

func instanceKeyFromDB(t *testing.T, dbPath string) string {
	t.Helper()
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	k, ok, err := d.GetMeta(context.Background(), db.MetaInstanceKey)
	if err != nil || !ok {
		t.Fatalf("GetMeta: ok=%v err=%v", ok, err)
	}
	return k
}

func runInitRoot(t *testing.T, dataDir, dbPath, hostname string) {
	t.Helper()
	cmd := cli.NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", hostname, "--user", "root", "--listen-ip", "127.0.0.1", "--no-prompt"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init: %v\n%s", err, out.String())
	}
}

func TestInit_TwoInstances_DistinctKeys(t *testing.T) {
	setInitPassphrases(t)
	d1 := t.TempDir()
	d2 := t.TempDir()
	runInitRoot(t, d1, filepath.Join(d1, "state.db"), "m1")
	runInitRoot(t, d2, filepath.Join(d2, "state.db"), "m2")

	k1 := instanceKeyFromDB(t, filepath.Join(d1, "state.db"))
	k2 := instanceKeyFromDB(t, filepath.Join(d2, "state.db"))
	if !is16Hex(k1) || !is16Hex(k2) {
		t.Fatalf("keys not 16-hex: %q %q", k1, k2)
	}
	if k1 == k2 {
		t.Errorf("two inits produced the same instance key %q", k1)
	}
}
