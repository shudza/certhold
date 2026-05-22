package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shudza/certhold/internal/db"
)

func runEnroll(t *testing.T, dbPath string, args ...string) (string, string, error) {
	t.Helper()
	cmd := NewRootCmd()
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	full := append([]string{"--db", dbPath, "enroll"}, args...)
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

func TestEnrollSuccess(t *testing.T) {
	dbPath := setupDB(t)
	stdout, stderr, err := runEnroll(t, dbPath, "new-vm", "--groups", "a,b")
	if err != nil {
		t.Fatalf("enroll: err=%v stderr=%s", err, stderr)
	}

	line := strings.TrimRight(stdout, "\n")
	if !strings.HasPrefix(line, `echo "`) {
		t.Fatalf("output should start with echo \": %q", line)
	}
	if !strings.HasSuffix(line, `" | base64 -d | bash`) {
		t.Fatalf(`output should end with " | base64 -d | bash: %q`, line)
	}
	if strings.Count(stdout, "\n") != 1 {
		t.Fatalf("expected exactly one trailing newline, got %d", strings.Count(stdout, "\n"))
	}

	encoded := strings.TrimSuffix(strings.TrimPrefix(line, `echo "`), `" | base64 -d | bash`)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	script := string(decoded)
	if !strings.Contains(script, "tar -xzC /") {
		t.Errorf("script missing tar -xzC /: %q", script)
	}
	if !strings.Contains(script, "/enroll/") {
		t.Errorf("script missing /enroll/<token>: %q", script)
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d.Close()

	startIdx := strings.Index(script, "/enroll/")
	rest := script[startIdx+len("/enroll/"):]
	endIdx := strings.IndexAny(rest, " \t\n|")
	if endIdx < 0 {
		t.Fatalf("could not isolate token in script: %q", script)
	}
	tok := rest[:endIdx]
	if tok == "" {
		t.Fatalf("empty token in script")
	}

	peer, groups, err := d.ConsumeToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if peer != "new-vm" {
		t.Errorf("peer = %q, want new-vm", peer)
	}
	if groups != "a,b" {
		t.Errorf("groups = %q, want a,b", groups)
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
	line := strings.TrimRight(stdout, "\n")
	encoded := strings.TrimSuffix(strings.TrimPrefix(line, `echo "`), `" | base64 -d | bash`)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	script := string(decoded)
	startIdx := strings.Index(script, "/enroll/")
	rest := script[startIdx+len("/enroll/"):]
	endIdx := strings.IndexAny(rest, " \t\n|")
	tok := rest[:endIdx]

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d.Close()
	_, groups, err := d.ConsumeToken(context.Background(), tok)
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
	dbPath := setupDB(t)
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--db", dbPath, "enroll", "vm-base", "--groups", "x", "--base-url", "https://example.test"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	line := strings.TrimRight(out.String(), "\n")
	encoded := strings.TrimSuffix(strings.TrimPrefix(line, `echo "`), `" | base64 -d | bash`)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(string(decoded), "https://example.test/enroll/") {
		t.Errorf("script does not use base-url: %q", string(decoded))
	}
}
