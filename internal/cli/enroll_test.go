package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	dbPath := filepath.Join(t.TempDir(), "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}
	return dbPath
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

	peer, groups, mode, tu, err := d.ConsumeToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if peer != "new-vm" {
		t.Errorf("peer = %q, want new-vm", peer)
	}
	if groups != "a,b" {
		t.Errorf("groups = %q, want a,b", groups)
	}
	if mode != db.ModeUser {
		t.Errorf("default mode = %q, want %q", mode, db.ModeUser)
	}
	if tu != "" {
		t.Errorf("default target_user = %q, want empty", tu)
	}
}

func TestEnrollDefaultUserEmpty(t *testing.T) {
	dbPath := setupDB(t)
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
	_, _, mode, tu, err := d.ConsumeToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if mode != db.ModeUser {
		t.Errorf("mode = %q, want %q", mode, db.ModeUser)
	}
	if tu != "" {
		t.Errorf("target_user = %q, want empty when --user is omitted", tu)
	}
}

func TestEnrollExplicitUserAlice(t *testing.T) {
	dbPath := setupDB(t)
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
	_, _, _, tu, err := d.ConsumeToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if tu != "alice" {
		t.Errorf("target_user = %q, want alice", tu)
	}
}

func TestEnrollModeRoot(t *testing.T) {
	dbPath := setupDB(t)
	stdout, stderr, err := runEnroll(t, dbPath, "rootvm", "--groups", "infra", "--mode", "root")
	if err != nil {
		t.Fatalf("enroll: err=%v stderr=%s", err, stderr)
	}
	tok := extractToken(t, stdout, "https://certhold.home.lan")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d.Close()
	_, _, mode, tu, err := d.ConsumeToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if mode != db.ModeRoot {
		t.Errorf("mode = %q, want %q", mode, db.ModeRoot)
	}
	if tu != "" {
		t.Errorf("target_user = %q, want empty for root mode", tu)
	}
}

func TestEnrollModeUserExplicitUser(t *testing.T) {
	dbPath := setupDB(t)
	stdout, stderr, err := runEnroll(t, dbPath, "uvm", "--groups", "infra", "--mode", "user", "--user", "alice")
	if err != nil {
		t.Fatalf("enroll: err=%v stderr=%s", err, stderr)
	}
	tok := extractToken(t, stdout, "https://certhold.home.lan")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d.Close()
	_, _, mode, tu, err := d.ConsumeToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if mode != db.ModeUser || tu != "alice" {
		t.Errorf("mode=%q user=%q", mode, tu)
	}
}

func TestEnrollInvalidMode(t *testing.T) {
	dbPath := setupDB(t)
	if _, _, err := runEnroll(t, dbPath, "vmx", "--groups", "a", "--mode", "weird"); err == nil {
		t.Fatal("expected error for invalid --mode")
	}
}

func TestEnrollDuplicateName(t *testing.T) {
	dbPath := setupDB(t)
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := d.InsertPeer(context.Background(), "new-vm", 1, "fp", []byte("k")); err != nil {
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
