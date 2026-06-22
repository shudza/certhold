package db

import (
	"context"
	"errors"
	"testing"
)

// insertTestPeer records a peer with the given groups, allowed-groups and a
// single enrollment token whose peer_name points at it.
func insertTestPeer(t *testing.T, d *DB, ctx context.Context, name, token string, groups, allowed []string) {
	t.Helper()
	if err := d.InsertPeer(ctx, name, 1, "fp-"+name, []byte("key-"+name), "", true, "pull-"+name); err != nil {
		t.Fatalf("InsertPeer(%s): %v", name, err)
	}
	if err := d.SetPeerGroups(ctx, name, groups); err != nil {
		t.Fatalf("SetPeerGroups(%s): %v", name, err)
	}
	if err := d.SetPeerAllowedGroups(ctx, name, allowed); err != nil {
		t.Fatalf("SetPeerAllowedGroups(%s): %v", name, err)
	}
	if err := d.InsertToken(ctx, token, name, "infra", "", nil); err != nil {
		t.Fatalf("InsertToken(%s): %v", name, err)
	}
}

func TestSetPeerInbound(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.InsertPeer(ctx, "alpha", 1, "fp-a", []byte("ka"), "", true, ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}

	if err := d.SetPeerInbound(ctx, "alpha", false); err != nil {
		t.Fatalf("SetPeerInbound: %v", err)
	}
	p, err := d.GetPeer(ctx, "alpha")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.Inbound {
		t.Error("inbound must be false after SetPeerInbound(false)")
	}

	if err := d.SetPeerInbound(ctx, "ghost", false); !errors.Is(err, ErrPeerNotFound) {
		t.Errorf("SetPeerInbound on missing peer: got %v, want ErrPeerNotFound", err)
	}
}

func TestDeletePeerRemovesAllAssociations(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	insertTestPeer(t, d, ctx, "alpha", "tok-alpha", []string{"infra", "db"}, []string{"ops"})

	if err := d.DeletePeer(ctx, "alpha"); err != nil {
		t.Fatalf("DeletePeer: %v", err)
	}

	if _, err := d.GetPeer(ctx, "alpha"); !errors.Is(err, ErrPeerNotFound) {
		t.Errorf("GetPeer after delete: got %v, want ErrPeerNotFound", err)
	}
	if _, err := d.GetPeerByPullToken(ctx, "pull-alpha"); !errors.Is(err, ErrPeerNotFound) {
		t.Errorf("GetPeerByPullToken after delete: got %v, want ErrPeerNotFound", err)
	}
	if gs, err := d.GetPeerGroups(ctx, "alpha"); err != nil || len(gs) != 0 {
		t.Errorf("GetPeerGroups after delete: groups=%v err=%v, want empty", gs, err)
	}
	if gs, err := d.GetPeerAllowedGroups(ctx, "alpha"); err != nil || len(gs) != 0 {
		t.Errorf("GetPeerAllowedGroups after delete: groups=%v err=%v, want empty", gs, err)
	}
	if _, _, _, _, err := d.ConsumeToken(ctx, "tok-alpha"); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("ConsumeToken after delete: got %v, want ErrTokenNotFound", err)
	}

	if err := d.DeletePeer(ctx, "alpha"); !errors.Is(err, ErrPeerNotFound) {
		t.Errorf("second DeletePeer: got %v, want ErrPeerNotFound", err)
	}
}

func TestDeletePeerLeavesOtherPeerIntact(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	insertTestPeer(t, d, ctx, "alpha", "tok-alpha", []string{"infra"}, []string{"ops"})
	insertTestPeer(t, d, ctx, "bravo", "tok-bravo", []string{"db", "web"}, []string{"infra"})

	if err := d.DeletePeer(ctx, "alpha"); err != nil {
		t.Fatalf("DeletePeer(alpha): %v", err)
	}

	if _, err := d.GetPeer(ctx, "bravo"); err != nil {
		t.Errorf("GetPeer(bravo) after deleting alpha: %v", err)
	}
	if gs, err := d.GetPeerGroups(ctx, "bravo"); err != nil || len(gs) != 2 {
		t.Errorf("GetPeerGroups(bravo): groups=%v err=%v, want 2", gs, err)
	}
	if gs, err := d.GetPeerAllowedGroups(ctx, "bravo"); err != nil || len(gs) != 1 {
		t.Errorf("GetPeerAllowedGroups(bravo): groups=%v err=%v, want 1", gs, err)
	}
	if p, err := d.GetPeerByPullToken(ctx, "pull-bravo"); err != nil || p.Name != "bravo" {
		t.Errorf("GetPeerByPullToken(bravo): peer=%v err=%v", p, err)
	}
	if peer, _, _, _, err := d.ConsumeToken(ctx, "tok-bravo"); err != nil || peer != "bravo" {
		t.Errorf("ConsumeToken(tok-bravo): peer=%q err=%v", peer, err)
	}
}
