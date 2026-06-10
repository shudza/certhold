package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shudza/certhold/internal/db"
)

func TestTuiMissingDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.sqlite")
	_, err := runList(t, "--db", path, "tui")
	if err == nil {
		t.Fatal("tui against a missing db should fail")
	}
	if !strings.Contains(err.Error(), "run 'certhold init' first") {
		t.Fatalf("error = %q, want init hint", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatal("tui must not create the db file")
	}
}

func TestTuiUninitializedDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite")
	d, err := db.Open(path)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, err = runList(t, "--db", path, "tui")
	if err == nil {
		t.Fatal("tui against an uninitialized db should fail")
	}
	if !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("error = %q, want not-initialized hint", err)
	}
}
