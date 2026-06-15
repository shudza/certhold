package db

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func caRowCount(t *testing.T, d *DB) int {
	t.Helper()
	var n int
	if err := d.sql.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM ca`).Scan(&n); err != nil {
		t.Fatalf("count ca rows: %v", err)
	}
	return n
}

// TestBackfillSeedsActiveCAForPreFixInstall simulates an install created before
// init learned to seed CA version 1: a DB with a peer but no ca row. Reopening
// (which runs migrate) must backfill version 1 as active.
func TestBackfillSeedsActiveCAForPreFixInstall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prefix.sqlite")
	ctx := context.Background()

	d, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := d.InsertPeer(ctx, "alpha", 7, "SHA256:abc", []byte("ssh-ed25519 AAAA-alpha"), "root", true, ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	if _, err := d.ActiveCAVersion(ctx); !errors.Is(err, ErrNoActiveCA) {
		t.Fatalf("precondition: want ErrNoActiveCA before reopen, got %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	d2, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer d2.Close()

	v, err := d2.ActiveCAVersion(ctx)
	if err != nil {
		t.Fatalf("ActiveCAVersion after backfill: %v", err)
	}
	if v != 1 {
		t.Errorf("ActiveCAVersion = %d, want 1", v)
	}
	if n := caRowCount(t, d2); n != 1 {
		t.Errorf("ca row count = %d, want 1", n)
	}
}

// TestBackfillSkipsEmptyDB asserts a brand-new DB with no peers is NOT
// backfilled: an empty/never-init'd DB must stay uninitialized.
func TestBackfillSkipsEmptyDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.sqlite")
	ctx := context.Background()

	d, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()

	if _, err := d.ActiveCAVersion(ctx); !errors.Is(err, ErrNoActiveCA) {
		t.Fatalf("ActiveCAVersion on empty DB = %v, want ErrNoActiveCA", err)
	}
	if n := caRowCount(t, d); n != 0 {
		t.Errorf("ca row count = %d, want 0 for empty DB", n)
	}
}

// TestBackfillDoesNotClobberRekeyedDB asserts a DB that already has an active
// ca row (e.g. version 3 from a rekey) is left untouched: no overwrite, no
// extra row.
func TestBackfillDoesNotClobberRekeyedDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rekeyed.sqlite")
	ctx := context.Background()

	d, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := d.InsertPeer(ctx, "beta", 9, "SHA256:def", []byte("ssh-ed25519 AAAA-beta"), "root", true, ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	if err := d.InsertCAVersion(ctx, 3); err != nil {
		t.Fatalf("InsertCAVersion: %v", err)
	}
	if err := d.SetActiveCAVersion(ctx, 3); err != nil {
		t.Fatalf("SetActiveCAVersion: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	d2, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer d2.Close()

	v, err := d2.ActiveCAVersion(ctx)
	if err != nil {
		t.Fatalf("ActiveCAVersion: %v", err)
	}
	if v != 3 {
		t.Errorf("ActiveCAVersion = %d, want 3 (no clobber)", v)
	}
	if n := caRowCount(t, d2); n != 1 {
		t.Errorf("ca row count = %d, want 1 (no extra row)", n)
	}
}

// TestBackfillIdempotent reopens an already-backfilled DB and asserts it still
// has exactly one ca row, version 1 active.
func TestBackfillIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idem.sqlite")
	ctx := context.Background()

	d, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := d.InsertPeer(ctx, "gamma", 11, "SHA256:ghi", []byte("ssh-ed25519 AAAA-gamma"), "root", true, ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for i := 0; i < 3; i++ {
		dx, err := Open(path)
		if err != nil {
			t.Fatalf("re-Open run %d: %v", i+1, err)
		}
		v, err := dx.ActiveCAVersion(ctx)
		if err != nil {
			t.Fatalf("ActiveCAVersion run %d: %v", i+1, err)
		}
		if v != 1 {
			t.Errorf("run %d: ActiveCAVersion = %d, want 1", i+1, v)
		}
		if n := caRowCount(t, dx); n != 1 {
			t.Errorf("run %d: ca row count = %d, want 1", i+1, n)
		}
		if err := dx.Close(); err != nil {
			t.Fatalf("Close run %d: %v", i+1, err)
		}
	}
}
