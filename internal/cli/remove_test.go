package cli_test

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shudza/certhold/internal/cli"
	"github.com/shudza/certhold/internal/db"
)

func seedRemoveDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "remove.sqlite")
	d, err := db.Open(path)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	ctx := t.Context()
	if err := d.InsertPeer(ctx, "alpha", 1, "fp-a", []byte("ka"), "", true, ""); err != nil {
		t.Fatalf("InsertPeer alpha: %v", err)
	}
	if err := d.InsertPeer(ctx, "beta", 2, "fp-b", []byte("kb"), "", true, ""); err != nil {
		t.Fatalf("InsertPeer beta: %v", err)
	}
	return path
}

func runRemove(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := cli.NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestRemoveCmdRegistered(t *testing.T) {
	for _, c := range cli.NewRootCmd().Commands() {
		if c.Name() == "remove" {
			return
		}
	}
	t.Fatal("remove command not registered on root")
}

func TestRemoveCmdRequiresExactlyOneArg(t *testing.T) {
	dbPath := seedRemoveDB(t)
	if _, err := runRemove(t, "--db", dbPath, "remove"); err == nil {
		t.Error("expected error with no args")
	}
	if _, err := runRemove(t, "--db", dbPath, "remove", "alpha", "beta"); err == nil {
		t.Error("expected error with two args")
	}
}

func TestRemoveCmdDeletesPeer(t *testing.T) {
	dbPath := seedRemoveDB(t)
	out, err := runRemove(t, "--db", dbPath, "remove", "alpha")
	if err != nil {
		t.Fatalf("remove: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "alpha") {
		t.Errorf("output should mention removed peer; got:\n%s", out)
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d.Close()
	ctx := t.Context()
	if _, err := d.GetPeer(ctx, "alpha"); err == nil {
		t.Error("alpha should be gone after remove")
	}
	if _, err := d.GetPeer(ctx, "beta"); err != nil {
		t.Errorf("beta should remain after removing alpha: %v", err)
	}
}

func TestRemoveCmdUnknownPeerErrors(t *testing.T) {
	dbPath := seedRemoveDB(t)
	if _, err := runRemove(t, "--db", dbPath, "remove", "nosuch"); err == nil {
		t.Error("expected error removing unknown peer")
	}
}
