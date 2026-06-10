package db

import (
	"errors"
	"reflect"
	"testing"
)

func TestCreateGroup_HappyPath(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.CreateGroup(ctx, "infra"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	ok, err := d.GroupExists(ctx, "infra")
	if err != nil {
		t.Fatalf("GroupExists: %v", err)
	}
	if !ok {
		t.Error("expected group to exist after CreateGroup")
	}
}

func TestCreateGroup_DuplicateErrors(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.CreateGroup(ctx, "dup"); err != nil {
		t.Fatalf("first CreateGroup: %v", err)
	}
	if err := d.CreateGroup(ctx, "dup"); !errors.Is(err, ErrGroupExists) {
		t.Errorf("second CreateGroup: got %v, want ErrGroupExists", err)
	}
}

func TestCreateGroup_InvalidName(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	for _, name := range []string{"", "   ", "\t\n"} {
		if err := d.CreateGroup(ctx, name); !errors.Is(err, ErrInvalidGroupName) {
			t.Errorf("CreateGroup(%q): got %v, want ErrInvalidGroupName", name, err)
		}
	}
}

func TestDeleteGroup_CascadesPeerMemberships(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.InsertPeer(ctx, "alpha", 1, "fp", []byte("k"), "", true, ""); err != nil {
		t.Fatalf("InsertPeer alpha: %v", err)
	}
	if err := d.InsertPeer(ctx, "beta", 2, "fp", []byte("k"), "", true, ""); err != nil {
		t.Fatalf("InsertPeer beta: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "alpha", []string{"infra", "db"}); err != nil {
		t.Fatalf("SetPeerGroups alpha: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "beta", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups beta: %v", err)
	}
	if err := d.DeleteGroup(ctx, "infra"); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	ok, err := d.GroupExists(ctx, "infra")
	if err != nil {
		t.Fatalf("GroupExists: %v", err)
	}
	if ok {
		t.Error("group still present after DeleteGroup")
	}
	members, err := d.GetGroupMembers(ctx, "infra")
	if err != nil {
		t.Fatalf("GetGroupMembers: %v", err)
	}
	if len(members) != 0 {
		t.Errorf("peer_groups not cleared: %v", members)
	}
	allowed, err := d.GetGroupAllowedBy(ctx, "infra")
	if err != nil {
		t.Fatalf("GetGroupAllowedBy: %v", err)
	}
	if len(allowed) != 0 {
		t.Errorf("peer_allowed_groups not cleared: %v", allowed)
	}
	// alpha's other membership (db) must survive.
	gs, err := d.GetPeerGroups(ctx, "alpha")
	if err != nil {
		t.Fatalf("GetPeerGroups: %v", err)
	}
	if !reflect.DeepEqual(gs, []string{"db"}) {
		t.Errorf("alpha groups after delete = %v, want [db]", gs)
	}
}

func TestDeleteGroup_NotFound(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.DeleteGroup(ctx, "ghost"); !errors.Is(err, ErrGroupNotFound) {
		t.Errorf("DeleteGroup missing: got %v, want ErrGroupNotFound", err)
	}
}

func TestRenameGroup_Success(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.InsertPeer(ctx, "p", 1, "fp", []byte("k"), "", true, ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "p", []string{"old"}); err != nil {
		t.Fatalf("SetPeerGroups: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "p", []string{"old"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups: %v", err)
	}
	if err := d.RenameGroup(ctx, "old", "new"); err != nil {
		t.Fatalf("RenameGroup: %v", err)
	}
	if ok, _ := d.GroupExists(ctx, "old"); ok {
		t.Error("old group should be gone")
	}
	if ok, _ := d.GroupExists(ctx, "new"); !ok {
		t.Error("new group should exist")
	}
	gs, err := d.GetPeerGroups(ctx, "p")
	if err != nil {
		t.Fatalf("GetPeerGroups: %v", err)
	}
	if !reflect.DeepEqual(gs, []string{"new"}) {
		t.Errorf("peer groups after rename = %v, want [new]", gs)
	}
	ags, err := d.GetPeerAllowedGroups(ctx, "p")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	if !reflect.DeepEqual(ags, []string{"new"}) {
		t.Errorf("peer allowed groups after rename = %v, want [new]", ags)
	}
}

func TestRenameGroup_TargetExists(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.CreateGroup(ctx, "src"); err != nil {
		t.Fatalf("CreateGroup src: %v", err)
	}
	if err := d.CreateGroup(ctx, "dst"); err != nil {
		t.Fatalf("CreateGroup dst: %v", err)
	}
	if err := d.RenameGroup(ctx, "src", "dst"); !errors.Is(err, ErrGroupExists) {
		t.Errorf("RenameGroup over existing: got %v, want ErrGroupExists", err)
	}
	if ok, _ := d.GroupExists(ctx, "src"); !ok {
		t.Error("src must still exist after failed rename")
	}
}

func TestRenameGroup_SourceMissing(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.RenameGroup(ctx, "ghost", "new"); !errors.Is(err, ErrGroupNotFound) {
		t.Errorf("RenameGroup missing source: got %v, want ErrGroupNotFound", err)
	}
}

func TestRenameGroup_InvalidNewName(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.CreateGroup(ctx, "src"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	for _, name := range []string{"", "   ", "\t"} {
		if err := d.RenameGroup(ctx, "src", name); !errors.Is(err, ErrInvalidGroupName) {
			t.Errorf("RenameGroup -> %q: got %v, want ErrInvalidGroupName", name, err)
		}
	}
}

func TestGetGroupMembersAndAllowedBy_Ordering(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	for _, n := range []string{"charlie", "alpha", "bravo"} {
		if err := d.InsertPeer(ctx, n, 1, "fp", []byte("k"), "", true, ""); err != nil {
			t.Fatalf("InsertPeer %s: %v", n, err)
		}
		if err := d.SetPeerGroups(ctx, n, []string{"infra"}); err != nil {
			t.Fatalf("SetPeerGroups %s: %v", n, err)
		}
		if err := d.SetPeerAllowedGroups(ctx, n, []string{"infra"}); err != nil {
			t.Fatalf("SetPeerAllowedGroups %s: %v", n, err)
		}
	}
	members, err := d.GetGroupMembers(ctx, "infra")
	if err != nil {
		t.Fatalf("GetGroupMembers: %v", err)
	}
	if !reflect.DeepEqual(members, []string{"alpha", "bravo", "charlie"}) {
		t.Errorf("GetGroupMembers = %v, want sorted", members)
	}
	allowed, err := d.GetGroupAllowedBy(ctx, "infra")
	if err != nil {
		t.Fatalf("GetGroupAllowedBy: %v", err)
	}
	if !reflect.DeepEqual(allowed, []string{"alpha", "bravo", "charlie"}) {
		t.Errorf("GetGroupAllowedBy = %v, want sorted", allowed)
	}
	empty, err := d.GetGroupMembers(ctx, "nope")
	if err != nil {
		t.Fatalf("GetGroupMembers empty: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("empty group members = %v, want []", empty)
	}
}

func TestTx_CreateAndDeleteGroup(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)

	err := d.WithTx(ctx, func(tx *Tx) error {
		if err := tx.CreateGroup(ctx, "txg"); err != nil {
			return err
		}
		ok, err := tx.GroupExists(ctx, "txg")
		if err != nil {
			return err
		}
		if !ok {
			t.Error("Tx.GroupExists should see uncommitted group")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithTx create: %v", err)
	}
	if ok, _ := d.GroupExists(ctx, "txg"); !ok {
		t.Error("group missing after committed tx")
	}

	err = d.WithTx(ctx, func(tx *Tx) error {
		return tx.DeleteGroup(ctx, "txg")
	})
	if err != nil {
		t.Fatalf("WithTx delete: %v", err)
	}
	if ok, _ := d.GroupExists(ctx, "txg"); ok {
		t.Error("group still present after Tx.DeleteGroup")
	}

	// Sentinel errors propagate through Tx wrappers too.
	err = d.WithTx(ctx, func(tx *Tx) error {
		return tx.DeleteGroup(ctx, "txg")
	})
	if !errors.Is(err, ErrGroupNotFound) {
		t.Errorf("Tx.DeleteGroup missing: got %v, want ErrGroupNotFound", err)
	}
	err = d.WithTx(ctx, func(tx *Tx) error {
		if err := tx.CreateGroup(ctx, "dupe"); err != nil {
			return err
		}
		return tx.CreateGroup(ctx, "dupe")
	})
	if !errors.Is(err, ErrGroupExists) {
		t.Errorf("Tx.CreateGroup duplicate: got %v, want ErrGroupExists", err)
	}
}
