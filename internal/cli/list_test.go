package cli_test

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shudza/certhold/internal/cli"
	"github.com/shudza/certhold/internal/db"
)

func seedListDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "list.sqlite")
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
	if err := d.SetPeerGroups(ctx, "alpha", []string{"infra", "db"}); err != nil {
		t.Fatalf("SetPeerGroups alpha: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "beta", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerGroups beta: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "alpha", []string{"ops"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups alpha: %v", err)
	}
	if err := d.SetPeerRevoked(ctx, "beta"); err != nil {
		t.Fatalf("SetPeerRevoked beta: %v", err)
	}
	return path
}

func runList(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := cli.NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestListPeersDefault(t *testing.T) {
	dbPath := seedListDB(t)
	got, err := runList(t, "--db", dbPath, "list")
	if err != nil {
		t.Fatalf("Execute: %v\noutput:\n%s", err, got)
	}
	for _, want := range []string{"NAME", "GROUPS", "ALLOWED", "REVOKED", "alpha", "beta"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in output:\n%s", want, got)
		}
	}
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected header + 2 rows, got %d lines:\n%s", len(lines), got)
	}
	idxAlpha, idxBeta := -1, -1
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "alpha") {
			idxAlpha = i
		}
		if strings.HasPrefix(strings.TrimSpace(line), "beta") {
			idxBeta = i
		}
	}
	if idxAlpha < 0 || idxBeta < 0 {
		t.Fatalf("rows missing: alpha=%d beta=%d\n%s", idxAlpha, idxBeta, got)
	}
	if idxAlpha > idxBeta {
		t.Errorf("alpha should come before beta:\n%s", got)
	}
	betaFields := strings.Fields(lines[idxBeta])
	if len(betaFields) < 3 || betaFields[len(betaFields)-1] != "Y" {
		t.Errorf("beta REVOKED column not Y: %q", lines[idxBeta])
	}
	alphaFields := strings.Fields(lines[idxAlpha])
	if len(alphaFields) < 4 || alphaFields[len(alphaFields)-1] != "N" {
		t.Errorf("alpha REVOKED column not N: %q", lines[idxAlpha])
	}
}

func TestListPeersFlag(t *testing.T) {
	dbPath := seedListDB(t)
	got, err := runList(t, "--db", dbPath, "list", "--peers")
	if err != nil {
		t.Fatalf("Execute: %v\noutput:\n%s", err, got)
	}
	if !strings.Contains(got, "alpha") || !strings.Contains(got, "beta") {
		t.Errorf("missing peers in --peers output:\n%s", got)
	}
}

func TestListGroups(t *testing.T) {
	dbPath := seedListDB(t)
	got, err := runList(t, "--db", dbPath, "list", "--groups")
	if err != nil {
		t.Fatalf("Execute: %v\noutput:\n%s", err, got)
	}
	for _, want := range []string{"NAME", "PEERS", "db", "infra"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in output:\n%s", want, got)
		}
	}
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		switch f[0] {
		case "db":
			if f[1] != "1" {
				t.Errorf("db count = %s, want 1", f[1])
			}
		case "infra":
			if f[1] != "2" {
				t.Errorf("infra count = %s, want 2", f[1])
			}
		}
	}
}

func TestListMutuallyExclusive(t *testing.T) {
	dbPath := seedListDB(t)
	_, err := runList(t, "--db", dbPath, "list", "--peers", "--groups")
	if err == nil {
		t.Fatal("expected error when both --peers and --groups passed")
	}
}
