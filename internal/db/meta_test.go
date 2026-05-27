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
