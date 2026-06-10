package db

import (
	"context"
	"testing"
)

func TestMetaRoundTrip(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if _, ok, err := d.GetMeta(ctx, "missing"); err != nil {
		t.Fatalf("GetMeta missing: %v", err)
	} else if ok {
		t.Errorf("missing key should return ok=false")
	}

	if err := d.SetMeta(ctx, MetaInstanceKey, "deadbeefcafef00d"); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	v, ok, err := d.GetMeta(ctx, MetaInstanceKey)
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}
	if !ok || v != "deadbeefcafef00d" {
		t.Errorf("GetMeta = (%q, %v), want (deadbeefcafef00d, true)", v, ok)
	}
}

func TestMetaOverwrite(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if err := d.SetMeta(ctx, "k", "first"); err != nil {
		t.Fatalf("SetMeta first: %v", err)
	}
	if err := d.SetMeta(ctx, "k", "second"); err != nil {
		t.Fatalf("SetMeta second: %v", err)
	}
	v, ok, err := d.GetMeta(ctx, "k")
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}
	if !ok || v != "second" {
		t.Errorf("overwrite: GetMeta = (%q, %v), want (second, true)", v, ok)
	}
}

func TestFleetRev(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	rev, err := d.FleetRev(ctx)
	if err != nil {
		t.Fatalf("FleetRev absent: %v", err)
	}
	if rev != 0 {
		t.Errorf("FleetRev absent = %d, want 0", rev)
	}

	if err := d.BumpFleetRev(ctx); err != nil {
		t.Fatalf("BumpFleetRev first: %v", err)
	}
	if rev, err = d.FleetRev(ctx); err != nil || rev != 1 {
		t.Errorf("after first bump: rev=%d err=%v, want 1", rev, err)
	}

	if err := d.BumpFleetRev(ctx); err != nil {
		t.Fatalf("BumpFleetRev second: %v", err)
	}
	if rev, err = d.FleetRev(ctx); err != nil || rev != 2 {
		t.Errorf("after second bump: rev=%d err=%v, want 2", rev, err)
	}
}

func TestFleetRevTx(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	err := d.WithTx(ctx, func(tx *Tx) error {
		rev, err := tx.FleetRev(ctx)
		if err != nil {
			return err
		}
		if rev != 0 {
			t.Errorf("Tx.FleetRev absent = %d, want 0", rev)
		}
		if err := tx.BumpFleetRev(ctx); err != nil {
			return err
		}
		rev, err = tx.FleetRev(ctx)
		if err != nil {
			return err
		}
		if rev != 1 {
			t.Errorf("Tx.FleetRev after bump = %d, want 1", rev)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithTx: %v", err)
	}

	rev, err := d.FleetRev(ctx)
	if err != nil {
		t.Fatalf("FleetRev after committed tx: %v", err)
	}
	if rev != 1 {
		t.Errorf("FleetRev after committed tx = %d, want 1", rev)
	}
}
