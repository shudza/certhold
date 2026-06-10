package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/clientcli"
	"github.com/shudza/certhold/internal/db"
)

func runEnroll(t *testing.T, dbPath string, args ...string) (string, string, error) {
	t.Helper()
	clearBaseURLEnv(t)
	cmd := NewRootCmd()
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	full := append([]string{"--db", dbPath, "--data-dir", filepath.Dir(dbPath), "enroll"}, args...)
	cmd.SetArgs(full)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), errBuf.String(), err
}

func setupDB(t *testing.T) string {
	t.Helper()
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}
	// enroll signs at mint, so it needs a CA in <data-dir>/ca. Generate a
	// plaintext one so LoadWithPassphrase loads it with no prompt.
	if _, err := ca.Generate(filepath.Join(dataDir, "ca")); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	return dbPath
}

func preCreateGroups(t *testing.T, dbPath string, groups ...string) {
	t.Helper()
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("preCreateGroups open: %v", err)
	}
	defer d.Close()
	for _, g := range groups {
		if err := d.EnsureGroup(context.Background(), g); err != nil {
			t.Fatalf("preCreateGroups EnsureGroup %q: %v", g, err)
		}
	}
}

// extractTokenTarball pulls the stored tarball blob for a token row directly via
// a fresh consume (the cli enroll path stores it; the byte-server would clear it).
func consumeTokenTarball(t *testing.T, dbPath, tok string) []byte {
	t.Helper()
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d.Close()
	_, _, _, tb, err := d.ConsumeToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	return tb
}

func extractTarEntries(t *testing.T, body []byte) map[string][]byte {
	t.Helper()
	entries, _ := extractTarEntriesWithModes(t, body)
	return entries
}

func extractTarEntriesWithModes(t *testing.T, body []byte) (map[string][]byte, map[string]int64) {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	modes := map[string]int64{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		out[hdr.Name] = data
		modes[hdr.Name] = hdr.Mode
	}
	return out, modes
}

func clearBaseURLEnv(t *testing.T) {
	t.Helper()
	prev, had := os.LookupEnv("CERTHOLD_BASE_URL")
	_ = os.Unsetenv("CERTHOLD_BASE_URL")
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("CERTHOLD_BASE_URL", prev)
		} else {
			_ = os.Unsetenv("CERTHOLD_BASE_URL")
		}
	})
}

func extractToken(t *testing.T, stdout, baseURL string) string {
	t.Helper()
	line := strings.TrimRight(stdout, "\n")
	prefix := "curl -kfsSL " + baseURL + "/enroll/"
	suffix := ".sh | bash"
	if !strings.HasPrefix(line, prefix) {
		t.Fatalf("output prefix mismatch: %q (want %q)", line, prefix)
	}
	if !strings.HasSuffix(line, suffix) {
		t.Fatalf("output suffix mismatch: %q (want %q)", line, suffix)
	}
	if strings.Count(stdout, "\n") != 1 {
		t.Fatalf("expected exactly one trailing newline, got %d", strings.Count(stdout, "\n"))
	}
	return strings.TrimSuffix(strings.TrimPrefix(line, prefix), suffix)
}

func TestEnrollSuccess(t *testing.T) {
	dbPath := setupDB(t)
	preCreateGroups(t, dbPath, "a", "b")
	stdout, stderr, err := runEnroll(t, dbPath, "new-vm", "--groups", "a,b")
	if err != nil {
		t.Fatalf("enroll: err=%v stderr=%s", err, stderr)
	}
	tok := extractToken(t, stdout, "https://certhold.home.lan")
	if tok == "" {
		t.Fatal("empty token")
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d.Close()

	peer, groups, tu, _, err := d.ConsumeToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if peer != "new-vm" {
		t.Errorf("peer = %q, want new-vm", peer)
	}
	if groups != "a,b" {
		t.Errorf("groups = %q, want a,b", groups)
	}
	if tu != "" {
		t.Errorf("default target_user = %q, want empty", tu)
	}
}

func TestEnrollAddressStoredOnPeerRow(t *testing.T) {
	dbPath := setupDB(t)
	preCreateGroups(t, dbPath, "infra")
	stdout, stderr, err := runEnroll(t, dbPath, "app1", "--groups", "infra", "--address", "10.0.0.5")
	if err != nil {
		t.Fatalf("enroll: err=%v stderr=%s", err, stderr)
	}
	if tok := extractToken(t, stdout, "https://certhold.home.lan"); tok == "" {
		t.Fatal("empty token")
	}
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d.Close()
	p, err := d.GetPeer(context.Background(), "app1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.Address != "10.0.0.5" {
		t.Errorf("Address = %q, want 10.0.0.5", p.Address)
	}
	if got := p.DialHost(); got != "10.0.0.5" {
		t.Errorf("DialHost = %q, want 10.0.0.5", got)
	}
}

func TestEnrollNoAddressLeavesEmpty(t *testing.T) {
	dbPath := setupDB(t)
	preCreateGroups(t, dbPath, "infra")
	if _, stderr, err := runEnroll(t, dbPath, "app2", "--groups", "infra"); err != nil {
		t.Fatalf("enroll: err=%v stderr=%s", err, stderr)
	}
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d.Close()
	p, err := d.GetPeer(context.Background(), "app2")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.Address != "" {
		t.Errorf("Address = %q, want empty (no --address)", p.Address)
	}
	if got := p.DialHost(); got != "app2" {
		t.Errorf("DialHost = %q, want app2 (the name)", got)
	}
}

func TestEnrollDefaultUserEmpty(t *testing.T) {
	dbPath := setupDB(t)
	preCreateGroups(t, dbPath, "infra")
	stdout, stderr, err := runEnroll(t, dbPath, "vm1", "--groups", "infra")
	if err != nil {
		t.Fatalf("enroll: err=%v stderr=%s", err, stderr)
	}
	tok := extractToken(t, stdout, "https://certhold.home.lan")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d.Close()
	_, _, tu, _, err := d.ConsumeToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if tu != "" {
		t.Errorf("target_user = %q, want empty when --user is omitted", tu)
	}
}

func TestEnrollExplicitUserAlice(t *testing.T) {
	dbPath := setupDB(t)
	preCreateGroups(t, dbPath, "infra")
	stdout, stderr, err := runEnroll(t, dbPath, "vm1", "--groups", "infra", "--user", "alice")
	if err != nil {
		t.Fatalf("enroll: err=%v stderr=%s", err, stderr)
	}
	tok := extractToken(t, stdout, "https://certhold.home.lan")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d.Close()
	_, _, tu, _, err := d.ConsumeToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if tu != "alice" {
		t.Errorf("target_user = %q, want alice", tu)
	}
}

// TestEnrollRootUser verifies a --user root enrollment stores target_user=root
// (root is reached by targeting the root user, not a removed root mode).
func TestEnrollRootUser(t *testing.T) {
	dbPath := setupDB(t)
	preCreateGroups(t, dbPath, "infra")
	stdout, stderr, err := runEnroll(t, dbPath, "rootvm", "--groups", "infra", "--user", "root")
	if err != nil {
		t.Fatalf("enroll: err=%v stderr=%s", err, stderr)
	}
	tok := extractToken(t, stdout, "https://certhold.home.lan")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d.Close()
	_, _, tu, _, err := d.ConsumeToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if tu != "root" {
		t.Errorf("target_user = %q, want root", tu)
	}
}

func TestEnrollExplicitUser(t *testing.T) {
	dbPath := setupDB(t)
	preCreateGroups(t, dbPath, "infra")
	stdout, stderr, err := runEnroll(t, dbPath, "uvm", "--groups", "infra", "--user", "alice")
	if err != nil {
		t.Fatalf("enroll: err=%v stderr=%s", err, stderr)
	}
	tok := extractToken(t, stdout, "https://certhold.home.lan")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d.Close()
	_, _, tu, _, err := d.ConsumeToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if tu != "alice" {
		t.Errorf("user=%q, want alice", tu)
	}
}

// TestEnrollModeFlagRemoved asserts the removed --mode flag is now rejected as
// an unknown flag.
func TestEnrollModeFlagRemoved(t *testing.T) {
	dbPath := setupDB(t)
	if _, _, err := runEnroll(t, dbPath, "vmx", "--groups", "a", "--mode", "user"); err == nil {
		t.Fatal("expected error for removed --mode flag")
	}
}

func TestEnrollDuplicateName(t *testing.T) {
	dbPath := setupDB(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := d.InsertPeer(context.Background(), "new-vm", 1, "fp", []byte("k"), "", true, ""); err != nil {
		t.Fatalf("InsertPeer setup: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}

	if _, _, err := runEnroll(t, dbPath, "new-vm", "--groups", "d"); err == nil {
		t.Fatal("expected enroll to fail for existing peer row")
	}
}

func TestEnrollGroupsDedupeAndTrim(t *testing.T) {
	dbPath := setupDB(t)
	preCreateGroups(t, dbPath, "a", "b", "c")
	stdout, stderr, err := runEnroll(t, dbPath, "vm2", "--groups", " a , b ,a, ,c")
	if err != nil {
		t.Fatalf("enroll: err=%v stderr=%s", err, stderr)
	}
	tok := extractToken(t, stdout, "https://certhold.home.lan")

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d.Close()
	_, groups, _, _, err := d.ConsumeToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if groups != "a,b,c" {
		t.Errorf("groups = %q, want a,b,c", groups)
	}
}

func TestEnrollEmptyGroups(t *testing.T) {
	dbPath := setupDB(t)
	if _, _, err := runEnroll(t, dbPath, "vm3", "--groups", " , , "); err == nil {
		t.Fatal("expected error for empty groups")
	}
}

func TestEnrollBaseURLFlag(t *testing.T) {
	clearBaseURLEnv(t)
	dbPath := setupDB(t)
	preCreateGroups(t, dbPath, "x")
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", filepath.Dir(dbPath), "enroll", "vm-base", "--groups", "x", "--base-url", "https://example.test"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	tok := extractToken(t, out.String(), "https://example.test")
	if tok == "" {
		t.Fatal("empty token")
	}
}

func TestEnrollBaseURLFromPersistedFile(t *testing.T) {
	clearBaseURLEnv(t)
	dbPath := setupDB(t)
	preCreateGroups(t, dbPath, "infra")
	dataDir := filepath.Dir(dbPath)
	if err := SaveBaseURL(dataDir, "https://192.168.1.205:8443"); err != nil {
		t.Fatalf("SaveBaseURL: %v", err)
	}
	stdout, stderr, err := runEnroll(t, dbPath, "persisted-vm", "--groups", "infra")
	if err != nil {
		t.Fatalf("enroll: err=%v stderr=%s", err, stderr)
	}
	if tok := extractToken(t, stdout, "https://192.168.1.205:8443"); tok == "" {
		t.Fatal("empty token")
	}
}

func TestEnrollBaseURLFlagBeatsPersisted(t *testing.T) {
	clearBaseURLEnv(t)
	dbPath := setupDB(t)
	preCreateGroups(t, dbPath, "x")
	dataDir := filepath.Dir(dbPath)
	if err := SaveBaseURL(dataDir, "https://192.168.1.205:8443"); err != nil {
		t.Fatalf("SaveBaseURL: %v", err)
	}
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "enroll", "vm-flag", "--groups", "x", "--base-url", "https://override.local"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if tok := extractToken(t, out.String(), "https://override.local"); tok == "" {
		t.Fatal("empty token")
	}
}

func TestEnrollBaseURLEnvBeatsPersistedNotFlag(t *testing.T) {
	clearBaseURLEnv(t)
	dbPath := setupDB(t)
	preCreateGroups(t, dbPath, "x")
	dataDir := filepath.Dir(dbPath)
	if err := SaveBaseURL(dataDir, "https://192.168.1.205:8443"); err != nil {
		t.Fatalf("SaveBaseURL: %v", err)
	}
	t.Setenv("CERTHOLD_BASE_URL", "http://env.example")

	// env beats persisted
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "enroll", "vm-env", "--groups", "x"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if tok := extractToken(t, out.String(), "http://env.example"); tok == "" {
		t.Fatal("empty token")
	}

	// flag beats env
	cmd2 := NewRootCmd()
	var out2 bytes.Buffer
	cmd2.SetOut(&out2)
	cmd2.SetErr(&out2)
	cmd2.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "enroll", "vm-flagwins", "--groups", "x", "--base-url", "https://flag.wins"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if tok := extractToken(t, out2.String(), "https://flag.wins"); tok == "" {
		t.Fatal("empty token")
	}
}

func instanceKeyOf(t *testing.T, dbPath string) string {
	t.Helper()
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	k, ok, err := d.GetMeta(context.Background(), db.MetaInstanceKey)
	if err != nil || !ok {
		t.Fatalf("GetMeta instance_key: ok=%v err=%v", ok, err)
	}
	return k
}

// TestEnrollBuildsRootTarball: a --user root enrollment yields the layout-v2
// namespaced user-style set targeting /root (no /etc/ssh files, no
// auth_principals/root).
func TestEnrollBuildsRootTarball(t *testing.T) {
	dbPath := setupDB(t)
	preCreateGroups(t, dbPath, "infra", "databases")
	stdout, stderr, err := runEnroll(t, dbPath, "rootvm", "--groups", "infra,databases", "--user", "root")
	if err != nil {
		t.Fatalf("enroll: err=%v stderr=%s", err, stderr)
	}
	tok := extractToken(t, stdout, "https://certhold.home.lan")
	key := instanceKeyOf(t, dbPath)

	tb := consumeTokenTarball(t, dbPath, tok)
	if tb == nil {
		t.Fatal("token row has nil tarball")
	}
	entries := extractTarEntries(t, tb)
	for _, n := range []string{"id_ed25519_" + key, "id_ed25519_" + key + "-cert.pub", "config", "ca_authorized_keys"} {
		if _, ok := entries[n]; !ok {
			t.Errorf("missing entry %q (have %v)", n, keysOf(entries))
		}
	}
	for _, forbidden := range []string{"etc/ssh/peer_ed25519", "etc/ssh/auth_principals/root", "authorized_keys"} {
		if _, ok := entries[forbidden]; ok {
			t.Errorf("v2 root tarball must not contain %q", forbidden)
		}
	}
	certBytes := entries["id_ed25519_"+key+"-cert.pub"]
	pk, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	cert := pk.(*ssh.Certificate)
	if cert.KeyId != "rootvm" {
		t.Errorf("KeyId = %q, want rootvm", cert.KeyId)
	}
	want := []string{"rootvm", "infra", "databases"}
	if strings.Join(cert.ValidPrincipals, ",") != strings.Join(want, ",") {
		t.Errorf("principals = %v, want %v", cert.ValidPrincipals, want)
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	p, err := d.GetPeer(context.Background(), "rootvm")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.Serial != cert.Serial {
		t.Errorf("peer serial %d != cert serial %d", p.Serial, cert.Serial)
	}
}

func TestEnrollBuildsUserTarball(t *testing.T) {
	dbPath := setupDB(t)
	preCreateGroups(t, dbPath, "infra")
	stdout, stderr, err := runEnroll(t, dbPath, "uvm", "--groups", "infra", "--user", "alice")
	if err != nil {
		t.Fatalf("enroll: err=%v stderr=%s", err, stderr)
	}
	tok := extractToken(t, stdout, "https://certhold.home.lan")
	key := instanceKeyOf(t, dbPath)
	tb := consumeTokenTarball(t, dbPath, tok)
	entries := extractTarEntries(t, tb)
	for _, n := range []string{"id_ed25519_" + key, "id_ed25519_" + key + "-cert.pub", "known_hosts", "config", "ca_authorized_keys"} {
		if _, ok := entries[n]; !ok {
			t.Errorf("missing user-mode entry %q (have %v)", n, keysOf(entries))
		}
	}
	if _, ok := entries["authorized_keys"]; ok {
		t.Errorf("v2 tarball must not ship a whole authorized_keys file")
	}
	ak := string(entries["ca_authorized_keys"])
	if !strings.HasPrefix(ak, `cert-authority,principals="manager,infra" `) {
		t.Errorf("ca_authorized_keys = %q", ak)
	}
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	p, err := d.GetPeer(context.Background(), "uvm")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.TargetUser != "alice" {
		t.Errorf("peer target_user = %q, want alice", p.TargetUser)
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestEnrollEncryptedCAViaEnv(t *testing.T) {
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	_ = d.Close()
	if _, err := ca.GenerateWithPassphrase(filepath.Join(dataDir, "ca"), []byte("capw")); err != nil {
		t.Fatalf("GenerateWithPassphrase: %v", err)
	}
	preCreateGroups(t, dbPath, "infra")

	t.Setenv("CERTHOLD_CA_PASSPHRASE", "capw")
	clearBaseURLEnv(t)
	cmd := NewRootCmd()
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "enroll", "encvm", "--groups", "infra"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("enroll with encrypted CA: err=%v stderr=%s", err, errBuf.String())
	}
	tok := extractToken(t, out.String(), "https://certhold.home.lan")
	key := instanceKeyOf(t, dbPath)
	tb := consumeTokenTarball(t, dbPath, tok)
	if tb == nil {
		t.Fatal("encrypted-CA enroll produced nil tarball")
	}
	entries := extractTarEntries(t, tb)
	if _, ok := entries["id_ed25519_"+key+"-cert.pub"]; !ok {
		t.Errorf("missing signed cert in encrypted-CA tarball (have %v)", keysOf(entries))
	}
}

// TestEnroll_FailsWhenGroupDoesNotExist verifies that enroll errors out (and
// does not insert the peer) when --groups references a group that has not been
// created via `certhold group create`.
func TestEnroll_FailsWhenGroupDoesNotExist(t *testing.T) {
	dbPath := setupDB(t)
	_, stderr, err := runEnroll(t, dbPath, "alpha", "--groups", "missing")
	if err == nil {
		t.Fatal("expected enroll to fail for nonexistent group, got nil")
	}
	msg := err.Error() + stderr
	if !strings.Contains(msg, "missing") {
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
	if _, gerr := d.GetPeer(context.Background(), "alpha"); !errors.Is(gerr, db.ErrPeerNotFound) {
		t.Errorf("peer alpha should not exist; GetPeer err = %v, want ErrPeerNotFound", gerr)
	}
}

// extractClientToken parses the client-enroll output: the curl one-liner
// followed by the client-style note. Returns the enroll token.
func extractClientToken(t *testing.T, stdout, baseURL string) string {
	t.Helper()
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("client enroll output = %q, want one-liner + note", stdout)
	}
	prefix := "curl -kfsSL " + baseURL + "/enroll/"
	suffix := ".sh | bash"
	if !strings.HasPrefix(lines[0], prefix) || !strings.HasSuffix(lines[0], suffix) {
		t.Fatalf("one-liner mismatch: %q", lines[0])
	}
	for _, want := range []string{"client-style peer", "manager cannot push", "certhold-cli refresh"} {
		if !strings.Contains(lines[1], want) {
			t.Errorf("client note %q missing %q", lines[1], want)
		}
	}
	return strings.TrimSuffix(strings.TrimPrefix(lines[0], prefix), suffix)
}

// TestEnrollClientFlag covers the --client path: peers row has inbound=0, a
// standing pull token and the cert blob; no allowed-groups rows; the tarball
// lacks ca_authorized_keys and carries certhold-cli (0755) plus the keyed conf
// (0600) with the exact 5 lines; the fleet rev is bumped.
func TestEnrollClientFlag(t *testing.T) {
	dbPath := setupDB(t)
	preCreateGroups(t, dbPath, "g")
	stdout, stderr, err := runEnroll(t, dbPath, "clientvm", "--groups", "g", "--client")
	if err != nil {
		t.Fatalf("enroll --client: err=%v stderr=%s", err, stderr)
	}
	tok := extractClientToken(t, stdout, "https://certhold.home.lan")
	key := instanceKeyOf(t, dbPath)

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d.Close()
	ctx := context.Background()

	p, err := d.GetPeer(ctx, "clientvm")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.Inbound {
		t.Error("Inbound = true, want false for --client")
	}
	if p.PullToken == "" {
		t.Error("PullToken is empty, want a standing pull token")
	}
	if len(p.Cert) == 0 {
		t.Error("Cert blob is empty, want the signed certificate stored")
	}
	allowed, err := d.GetPeerAllowedGroups(ctx, "clientvm")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	if len(allowed) != 0 {
		t.Errorf("allowed groups = %v, want none for --client", allowed)
	}
	member, err := d.GetPeerGroups(ctx, "clientvm")
	if err != nil {
		t.Fatalf("GetPeerGroups: %v", err)
	}
	if strings.Join(member, ",") != "g" {
		t.Errorf("peer groups = %v, want [g]", member)
	}
	rev, err := d.FleetRev(ctx)
	if err != nil {
		t.Fatalf("FleetRev: %v", err)
	}
	if rev != 1 {
		t.Errorf("fleet rev = %d, want 1 after one enroll", rev)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}

	tb := consumeTokenTarball(t, dbPath, tok)
	entries, modes := extractTarEntriesWithModes(t, tb)
	if _, ok := entries["ca_authorized_keys"]; ok {
		t.Errorf("client tarball must not contain ca_authorized_keys (have %v)", keysOf(entries))
	}
	if !bytes.Equal(entries["certhold-cli"], clientcli.Script) {
		t.Errorf("certhold-cli entry differs from clientcli.Script (have %v)", keysOf(entries))
	}
	if modes["certhold-cli"] != 0o755 {
		t.Errorf("certhold-cli mode = %o, want 0755", modes["certhold-cli"])
	}
	confName := "certhold_" + key + ".conf"
	if modes[confName] != 0o600 {
		t.Errorf("%s mode = %o, want 0600", confName, modes[confName])
	}
	wantConf := "BASE_URL=https://certhold.home.lan\nPULL_TOKEN=" + p.PullToken + "\nINSTANCE_KEY=" + key + "\nPEER_NAME=clientvm\nLAST_REV=0\n"
	if got := string(entries[confName]); got != wantConf {
		t.Errorf("conf = %q, want %q", got, wantConf)
	}
	if p.Cert != nil && !bytes.Equal(entries["id_ed25519_"+key+"-cert.pub"], p.Cert) {
		t.Error("stored cert blob differs from the tarball certificate")
	}
}

// TestEnrollNoInboundMatchesClient asserts --no-inbound behaves identically to
// --client on the DB row and the tarball shape.
func TestEnrollNoInboundMatchesClient(t *testing.T) {
	dbPath := setupDB(t)
	preCreateGroups(t, dbPath, "g")
	stdout, stderr, err := runEnroll(t, dbPath, "nivm", "--groups", "g", "--no-inbound")
	if err != nil {
		t.Fatalf("enroll --no-inbound: err=%v stderr=%s", err, stderr)
	}
	tok := extractClientToken(t, stdout, "https://certhold.home.lan")

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d.Close()
	ctx := context.Background()
	p, err := d.GetPeer(ctx, "nivm")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.Inbound {
		t.Error("Inbound = true, want false for --no-inbound")
	}
	if p.PullToken == "" {
		t.Error("PullToken is empty")
	}
	allowed, err := d.GetPeerAllowedGroups(ctx, "nivm")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	if len(allowed) != 0 {
		t.Errorf("allowed groups = %v, want none", allowed)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}

	entries := extractTarEntries(t, consumeTokenTarball(t, dbPath, tok))
	if _, ok := entries["ca_authorized_keys"]; ok {
		t.Error("--no-inbound tarball must not contain ca_authorized_keys")
	}
	if _, ok := entries["certhold-cli"]; !ok {
		t.Error("--no-inbound tarball missing certhold-cli")
	}
}

// TestEnrollDefaultBackCompat: a default (host-style) enroll keeps inbound=1
// and allowed groups, still ships ca_authorized_keys, and additionally carries
// the new pull token, stored cert, cli and conf entries.
func TestEnrollDefaultBackCompat(t *testing.T) {
	dbPath := setupDB(t)
	preCreateGroups(t, dbPath, "g")
	stdout, stderr, err := runEnroll(t, dbPath, "hostvm", "--groups", "g")
	if err != nil {
		t.Fatalf("enroll: err=%v stderr=%s", err, stderr)
	}
	tok := extractToken(t, stdout, "https://certhold.home.lan")
	key := instanceKeyOf(t, dbPath)

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d.Close()
	ctx := context.Background()
	p, err := d.GetPeer(ctx, "hostvm")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if !p.Inbound {
		t.Error("Inbound = false, want true for a default enroll")
	}
	if p.PullToken == "" {
		t.Error("PullToken is empty, want a standing pull token on every enroll")
	}
	if len(p.Cert) == 0 {
		t.Error("Cert blob is empty, want the signed certificate stored")
	}
	allowed, err := d.GetPeerAllowedGroups(ctx, "hostvm")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	if strings.Join(allowed, ",") != "g" {
		t.Errorf("allowed groups = %v, want [g]", allowed)
	}
	rev, err := d.FleetRev(ctx)
	if err != nil {
		t.Fatalf("FleetRev: %v", err)
	}
	if rev != 1 {
		t.Errorf("fleet rev = %d, want 1 after one enroll", rev)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}

	entries, modes := extractTarEntriesWithModes(t, consumeTokenTarball(t, dbPath, tok))
	for _, n := range []string{"ca_authorized_keys", "certhold-cli", "certhold_" + key + ".conf"} {
		if _, ok := entries[n]; !ok {
			t.Errorf("default tarball missing %q (have %v)", n, keysOf(entries))
		}
	}
	if modes["certhold-cli"] != 0o755 {
		t.Errorf("certhold-cli mode = %o, want 0755", modes["certhold-cli"])
	}
	if modes["certhold_"+key+".conf"] != 0o600 {
		t.Errorf("conf mode = %o, want 0600", modes["certhold_"+key+".conf"])
	}
	wantConf := "BASE_URL=https://certhold.home.lan\nPULL_TOKEN=" + p.PullToken + "\nINSTANCE_KEY=" + key + "\nPEER_NAME=hostvm\nLAST_REV=0\n"
	if got := string(entries["certhold_"+key+".conf"]); got != wantConf {
		t.Errorf("conf = %q, want %q", got, wantConf)
	}
}

// TestEnrollHostBlockForReachablePeer: enrolling B after A (which allows one of
// B's groups) puts a `Host A` stanza with A's address/user into B's config.
func TestEnrollHostBlockForReachablePeer(t *testing.T) {
	dbPath := setupDB(t)
	preCreateGroups(t, dbPath, "g")
	if _, stderr, err := runEnroll(t, dbPath, "peerA", "--groups", "g", "--address", "10.0.0.7", "--user", "alice"); err != nil {
		t.Fatalf("enroll peerA: err=%v stderr=%s", err, stderr)
	}
	stdout, stderr, err := runEnroll(t, dbPath, "peerB", "--groups", "g")
	if err != nil {
		t.Fatalf("enroll peerB: err=%v stderr=%s", err, stderr)
	}
	tok := extractToken(t, stdout, "https://certhold.home.lan")

	entries := extractTarEntries(t, consumeTokenTarball(t, dbPath, tok))
	cfg := string(entries["config"])
	want := "Host peerA\n    HostName 10.0.0.7\n    User alice\n"
	if !strings.Contains(cfg, want) {
		t.Errorf("peerB config missing %q\nconfig:\n%s", want, cfg)
	}
	if strings.Contains(cfg, "Host peerB\n") {
		t.Errorf("peerB config must not contain a Host stanza for itself\nconfig:\n%s", cfg)
	}
}

func TestEnrollWrongCAPassphraseFails(t *testing.T) {
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	_ = d.Close()
	if _, err := ca.GenerateWithPassphrase(filepath.Join(dataDir, "ca"), []byte("right")); err != nil {
		t.Fatalf("GenerateWithPassphrase: %v", err)
	}
	t.Setenv("CERTHOLD_CA_PASSPHRASE", "wrong")
	clearBaseURLEnv(t)
	cmd := NewRootCmd()
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "enroll", "badvm", "--groups", "infra"})
	if err := cmd.ExecuteContext(context.Background()); err == nil {
		t.Fatal("enroll with wrong CA passphrase: want error, got nil")
	}
}
