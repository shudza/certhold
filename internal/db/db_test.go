package db

import (
	"bytes"
	"errors"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
)

func newTestDB(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.sqlite")
	d, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestOpenIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idem.sqlite")
	d1, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := d1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	d2, err := Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	if err := d2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestOpenCreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "nested", "ch.sqlite")
	d, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()
}

func TestInsertAndGetPeer(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	key := []byte("ssh-ed25519 AAAA...")
	if err := d.InsertPeer(ctx, "alpha", 42, "SHA256:abc", key, "alice"); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	p, err := d.GetPeer(ctx, "alpha")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.Name != "alpha" || p.Serial != 42 || p.Fingerprint != "SHA256:abc" {
		t.Errorf("peer fields wrong: %+v", p)
	}
	if string(p.AuthorizedKey) != string(key) {
		t.Errorf("authorized key roundtrip mismatch")
	}
	if p.Revoked {
		t.Error("expected not revoked")
	}
	if p.TargetUser != "alice" {
		t.Errorf("TargetUser = %q, want alice", p.TargetUser)
	}
	if p.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
}

func TestGetPeerNotFound(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	_, err := d.GetPeer(ctx, "nope")
	if !errors.Is(err, ErrPeerNotFound) {
		t.Errorf("expected ErrPeerNotFound, got %v", err)
	}
}

func TestListPeers(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if peers, err := d.ListPeers(ctx); err != nil || len(peers) != 0 {
		t.Fatalf("empty list peers: err=%v len=%d", err, len(peers))
	}
	for _, n := range []string{"b", "a", "c"} {
		if err := d.InsertPeer(ctx, n, 1, "fp", []byte("k"), ""); err != nil {
			t.Fatalf("InsertPeer %s: %v", n, err)
		}
	}
	peers, err := d.ListPeers(ctx)
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(peers) != 3 {
		t.Fatalf("want 3 peers, got %d", len(peers))
	}
	if peers[0].Name != "a" || peers[1].Name != "b" || peers[2].Name != "c" {
		t.Errorf("peers not sorted: %v %v %v", peers[0].Name, peers[1].Name, peers[2].Name)
	}
}

func TestSetPeerRevoked(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.InsertPeer(ctx, "peer1", 1, "fp", []byte("k"), ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	if err := d.SetPeerRevoked(ctx, "peer1"); err != nil {
		t.Fatalf("SetPeerRevoked: %v", err)
	}
	p, err := d.GetPeer(ctx, "peer1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if !p.Revoked {
		t.Error("expected revoked")
	}
	if err := d.SetPeerRevoked(ctx, "missing"); !errors.Is(err, ErrPeerNotFound) {
		t.Errorf("revoke missing: %v", err)
	}
}

func TestEnsureGroup(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.EnsureGroup(ctx, "infra"); err != nil {
		t.Fatalf("EnsureGroup: %v", err)
	}
	if err := d.EnsureGroup(ctx, "infra"); err != nil {
		t.Fatalf("EnsureGroup repeat: %v", err)
	}
}

func TestSetGetPeerGroups(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.InsertPeer(ctx, "p", 1, "fp", []byte("k"), ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "p", []string{"infra", "db"}); err != nil {
		t.Fatalf("SetPeerGroups: %v", err)
	}
	gs, err := d.GetPeerGroups(ctx, "p")
	if err != nil {
		t.Fatalf("GetPeerGroups: %v", err)
	}
	sort.Strings(gs)
	if len(gs) != 2 || gs[0] != "db" || gs[1] != "infra" {
		t.Errorf("groups = %v", gs)
	}
	if err := d.SetPeerGroups(ctx, "p", []string{"web"}); err != nil {
		t.Fatalf("SetPeerGroups replace: %v", err)
	}
	gs, _ = d.GetPeerGroups(ctx, "p")
	if len(gs) != 1 || gs[0] != "web" {
		t.Errorf("after replace: %v", gs)
	}
	if err := d.SetPeerGroups(ctx, "p", nil); err != nil {
		t.Fatalf("clear groups: %v", err)
	}
	gs, _ = d.GetPeerGroups(ctx, "p")
	if len(gs) != 0 {
		t.Errorf("after clear: %v", gs)
	}
}

func TestSetGetPeerAllowedGroups(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.InsertPeer(ctx, "p", 1, "fp", []byte("k"), ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "p", []string{"ops", "infra"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups: %v", err)
	}
	gs, err := d.GetPeerAllowedGroups(ctx, "p")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	sort.Strings(gs)
	if len(gs) != 2 || gs[0] != "infra" || gs[1] != "ops" {
		t.Errorf("allowed groups = %v", gs)
	}
	if err := d.SetPeerAllowedGroups(ctx, "p", []string{"web"}); err != nil {
		t.Fatalf("replace: %v", err)
	}
	gs, _ = d.GetPeerAllowedGroups(ctx, "p")
	if len(gs) != 1 || gs[0] != "web" {
		t.Errorf("after replace: %v", gs)
	}
}

func TestListGroupsWithPeerCount(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if gs, err := d.ListGroupsWithPeerCount(ctx); err != nil || len(gs) != 0 {
		t.Fatalf("empty: err=%v len=%d", err, len(gs))
	}
	if err := d.InsertPeer(ctx, "alpha", 1, "fp", []byte("k"), ""); err != nil {
		t.Fatalf("InsertPeer alpha: %v", err)
	}
	if err := d.InsertPeer(ctx, "beta", 2, "fp", []byte("k"), ""); err != nil {
		t.Fatalf("InsertPeer beta: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "alpha", []string{"infra", "db"}); err != nil {
		t.Fatalf("SetPeerGroups alpha: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "beta", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerGroups beta: %v", err)
	}
	if err := d.EnsureGroup(ctx, "empty"); err != nil {
		t.Fatalf("EnsureGroup empty: %v", err)
	}
	gs, err := d.ListGroupsWithPeerCount(ctx)
	if err != nil {
		t.Fatalf("ListGroupsWithPeerCount: %v", err)
	}
	want := map[string]int{"db": 1, "infra": 2, "empty": 0}
	if len(gs) != len(want) {
		t.Fatalf("got %d groups, want %d: %+v", len(gs), len(want), gs)
	}
	for i, g := range gs {
		if i > 0 && gs[i-1].Name >= g.Name {
			t.Errorf("groups not sorted: %+v", gs)
		}
		if got, ok := want[g.Name]; !ok || got != g.PeerCount {
			t.Errorf("group %q: count=%d want=%d", g.Name, g.PeerCount, got)
		}
	}
}

func TestInsertConsumeToken(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.InsertToken(ctx, "tok1", "alpha", "infra,db", "", nil); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}
	peer, groups, tu, tarball, err := d.ConsumeToken(ctx, "tok1")
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if peer != "alpha" || groups != "infra,db" {
		t.Errorf("got peer=%q groups=%q", peer, groups)
	}
	if tu != "" {
		t.Errorf("target_user = %q, want empty", tu)
	}
	if tarball != nil {
		t.Errorf("nil-tarball token should yield nil tarball, got %d bytes", len(tarball))
	}
	if _, _, _, _, err := d.ConsumeToken(ctx, "tok1"); !errors.Is(err, ErrTokenAlreadyConsumed) {
		t.Errorf("second consume: %v", err)
	}
	if _, _, _, _, err := d.ConsumeToken(ctx, "missing"); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("missing token: %v", err)
	}
}

func TestInsertTokenRoundTrips(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	wantTarball := []byte("tarball-bytes-vmU")
	if err := d.InsertToken(ctx, "tokU", "vmU", "infra", "alice", wantTarball); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}
	peer, groups, tu, consumed, err := d.LookupToken(ctx, "tokU")
	if err != nil {
		t.Fatalf("LookupToken: %v", err)
	}
	if peer != "vmU" || groups != "infra" || tu != "alice" || consumed {
		t.Errorf("got peer=%q groups=%q tu=%q consumed=%v", peer, groups, tu, consumed)
	}
	peer, groups, tu, tarball, err := d.ConsumeToken(ctx, "tokU")
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if peer != "vmU" || groups != "infra" || tu != "alice" {
		t.Errorf("consume got peer=%q groups=%q tu=%q", peer, groups, tu)
	}
	if !bytes.Equal(tarball, wantTarball) {
		t.Errorf("consume tarball = %q, want %q", tarball, wantTarball)
	}
}

func TestConsumeTokenClearsBlob(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.InsertToken(ctx, "tokB", "vmB", "infra", "", []byte("blob")); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}
	if _, _, _, tarball, err := d.ConsumeToken(ctx, "tokB"); err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	} else if !bytes.Equal(tarball, []byte("blob")) {
		t.Errorf("tarball = %q, want blob", tarball)
	}
	var raw []byte
	if err := d.sql.QueryRowContext(ctx, `SELECT tarball FROM tokens WHERE token = ?`, "tokB").Scan(&raw); err != nil {
		t.Fatalf("select tarball: %v", err)
	}
	if raw != nil {
		t.Errorf("tarball not NULL after consume: %v", raw)
	}
}

func TestLookupToken(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if _, _, _, _, err := d.LookupToken(ctx, "missing"); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("missing: %v", err)
	}
	if err := d.InsertToken(ctx, "tokL", "peerL", "g1,g2", "", nil); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}
	peer, groups, tu, consumed, err := d.LookupToken(ctx, "tokL")
	if err != nil {
		t.Fatalf("LookupToken unconsumed: %v", err)
	}
	if peer != "peerL" || groups != "g1,g2" || consumed || tu != "" {
		t.Errorf("got peer=%q groups=%q tu=%q consumed=%v", peer, groups, tu, consumed)
	}
	if _, _, _, _, err := d.ConsumeToken(ctx, "tokL"); err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	peer, groups, _, consumed, err = d.LookupToken(ctx, "tokL")
	if err != nil {
		t.Fatalf("LookupToken consumed: %v", err)
	}
	if peer != "peerL" || groups != "g1,g2" || !consumed {
		t.Errorf("after consume got peer=%q groups=%q consumed=%v", peer, groups, consumed)
	}
}

func TestConsumeTokenRace(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.InsertToken(ctx, "race", "p", "g", "", nil); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}
	const n = 10
	var wg sync.WaitGroup
	var success int64
	var already int64
	var other int64
	wg.Add(n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			_, _, _, _, err := d.ConsumeToken(ctx, "race")
			switch {
			case err == nil:
				atomic.AddInt64(&success, 1)
			case errors.Is(err, ErrTokenAlreadyConsumed):
				atomic.AddInt64(&already, 1)
			default:
				atomic.AddInt64(&other, 1)
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if success != 1 {
		t.Errorf("expected exactly 1 success, got %d", success)
	}
	if already != n-1 {
		t.Errorf("expected %d ErrTokenAlreadyConsumed, got %d", n-1, already)
	}
	if other != 0 {
		t.Errorf("unexpected errors: %d", other)
	}
}

func TestInsertPeerDefaultsTargetUserEmpty(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.InsertPeer(ctx, "fresh", 1, "fp", []byte("k"), ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	p, err := d.GetPeer(ctx, "fresh")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.TargetUser != "" {
		t.Errorf("unredeemed peer should have empty target_user; got %q", p.TargetUser)
	}
}

func TestSetPeerTargetUser(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.InsertPeer(ctx, "vmU", 1, "fp", []byte("k"), ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	if err := d.SetPeerTargetUser(ctx, "vmU", "carol"); err != nil {
		t.Fatalf("SetPeerTargetUser: %v", err)
	}
	p, err := d.GetPeer(ctx, "vmU")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.TargetUser != "carol" {
		t.Errorf("target_user = %q, want carol", p.TargetUser)
	}
	if err := d.SetPeerTargetUser(ctx, "missing", "x"); !errors.Is(err, ErrPeerNotFound) {
		t.Errorf("SetPeerTargetUser missing: %v, want ErrPeerNotFound", err)
	}
}

func TestDialHost(t *testing.T) {
	p := &Peer{Name: "app1"}
	if got := p.DialHost(); got != "app1" {
		t.Errorf("DialHost with empty address = %q, want app1 (the name)", got)
	}
	p.Address = "10.0.0.5"
	if got := p.DialHost(); got != "10.0.0.5" {
		t.Errorf("DialHost with address set = %q, want 10.0.0.5", got)
	}
}

func TestSetPeerAddress(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.InsertPeer(ctx, "app1", 1, "fp", []byte("k"), ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	if p, _ := d.GetPeer(ctx, "app1"); p.Address != "" {
		t.Errorf("fresh peer Address = %q, want empty", p.Address)
	}
	if err := d.SetPeerAddress(ctx, "app1", "10.0.0.5"); err != nil {
		t.Fatalf("SetPeerAddress: %v", err)
	}
	p, err := d.GetPeer(ctx, "app1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.Address != "10.0.0.5" {
		t.Errorf("Address = %q, want 10.0.0.5", p.Address)
	}
	if got := p.DialHost(); got != "10.0.0.5" {
		t.Errorf("DialHost = %q, want 10.0.0.5", got)
	}
	if err := d.SetPeerAddress(ctx, "missing", "x"); !errors.Is(err, ErrPeerNotFound) {
		t.Errorf("SetPeerAddress missing: %v, want ErrPeerNotFound", err)
	}
}

func TestSetPeerAddressIfEmpty(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.InsertPeer(ctx, "app1", 1, "fp", []byte("k"), ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}

	// Sets the address when the peer currently has none.
	if err := d.SetPeerAddressIfEmpty(ctx, "app1", "10.0.0.5"); err != nil {
		t.Fatalf("SetPeerAddressIfEmpty (empty): %v", err)
	}
	if p, _ := d.GetPeer(ctx, "app1"); p.Address != "10.0.0.5" {
		t.Errorf("Address = %q, want 10.0.0.5", p.Address)
	}

	// No-op when an address is already set (explicit enroll --address wins).
	if err := d.SetPeerAddressIfEmpty(ctx, "app1", "192.168.1.9"); err != nil {
		t.Fatalf("SetPeerAddressIfEmpty (already set): %v", err)
	}
	if p, _ := d.GetPeer(ctx, "app1"); p.Address != "10.0.0.5" {
		t.Errorf("Address = %q, want 10.0.0.5 (must not overwrite an existing address)", p.Address)
	}

	// Matching 0 rows (no such peer) is not an error.
	if err := d.SetPeerAddressIfEmpty(ctx, "missing", "1.2.3.4"); err != nil {
		t.Errorf("SetPeerAddressIfEmpty on missing peer should be a no-op, got %v", err)
	}
}

func TestTxSetPeerAddress(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	err := d.WithTx(ctx, func(tx *Tx) error {
		if err := tx.InsertPeer(ctx, "app1", 1, "fp", []byte("k"), ""); err != nil {
			return err
		}
		return tx.SetPeerAddress(ctx, "app1", "10.0.0.5")
	})
	if err != nil {
		t.Fatalf("WithTx: %v", err)
	}
	p, err := d.GetPeer(ctx, "app1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.Address != "10.0.0.5" {
		t.Errorf("Address = %q, want 10.0.0.5", p.Address)
	}
}

func TestInsertPeerRoundTrips(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if err := d.InsertPeer(ctx, "vm", 1, "fp", []byte("k"), "alice"); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	p, err := d.GetPeer(ctx, "vm")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.TargetUser != "alice" {
		t.Errorf("got tu=%q, want alice", p.TargetUser)
	}
	ps, err := d.ListPeers(ctx)
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(ps) != 1 || ps[0].TargetUser != "alice" {
		t.Errorf("ListPeers populated target_user wrong: %+v", ps)
	}
}

func TestWithTxCommitsAtomically(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)

	err := d.WithTx(ctx, func(tx *Tx) error {
		if err := tx.InsertToken(ctx, "tokA", "vmA", "infra", "", []byte("tar")); err != nil {
			return err
		}
		if err := tx.InsertPeer(ctx, "vmA", 7, "fp", []byte("k"), ""); err != nil {
			return err
		}
		if err := tx.EnsureGroup(ctx, "infra"); err != nil {
			return err
		}
		if err := tx.SetPeerGroups(ctx, "vmA", []string{"infra"}); err != nil {
			return err
		}
		return tx.SetPeerAllowedGroups(ctx, "vmA", []string{"infra"})
	})
	if err != nil {
		t.Fatalf("WithTx: %v", err)
	}

	if _, _, _, _, err := d.LookupToken(ctx, "tokA"); err != nil {
		t.Fatalf("token row missing after committed tx: %v", err)
	}
	if _, err := d.GetPeer(ctx, "vmA"); err != nil {
		t.Fatalf("peer row missing after committed tx: %v", err)
	}
	groups, err := d.GetPeerGroups(ctx, "vmA")
	if err != nil {
		t.Fatalf("GetPeerGroups: %v", err)
	}
	if len(groups) != 1 || groups[0] != "infra" {
		t.Errorf("groups = %v, want [infra]", groups)
	}
}

// TestWithTxRollsBackOrphanedToken mirrors the enroll insert order (token row
// first, then the peer row) and forces the peer insert to fail with a primary
// key conflict. It asserts the token row is rolled back rather than orphaned —
// the exact regression that motivated wrapping enroll's inserts in a tx.
func TestWithTxRollsBackOrphanedToken(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)

	if err := d.InsertPeer(ctx, "dup", 1, "fp", []byte("k"), ""); err != nil {
		t.Fatalf("seed peer: %v", err)
	}

	err := d.WithTx(ctx, func(tx *Tx) error {
		if err := tx.InsertToken(ctx, "orphan-tok", "dup", "infra", "", []byte("tar")); err != nil {
			return err
		}
		return tx.InsertPeer(ctx, "dup", 2, "fp2", []byte("k2"), "")
	})
	if err == nil {
		t.Fatal("expected duplicate peer insert to fail the tx")
	}

	if _, _, _, _, lerr := d.LookupToken(ctx, "orphan-tok"); !errors.Is(lerr, ErrTokenNotFound) {
		t.Fatalf("token row survived a rolled-back tx (orphaned): err=%v", lerr)
	}
}

func TestCAVersions(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)
	if _, err := d.ActiveCAVersion(ctx); !errors.Is(err, ErrNoActiveCA) {
		t.Errorf("expected ErrNoActiveCA, got %v", err)
	}
	if err := d.InsertCAVersion(ctx, 1); err != nil {
		t.Fatalf("InsertCAVersion 1: %v", err)
	}
	if err := d.InsertCAVersion(ctx, 2); err != nil {
		t.Fatalf("InsertCAVersion 2: %v", err)
	}
	if err := d.SetActiveCAVersion(ctx, 1); err != nil {
		t.Fatalf("SetActiveCAVersion 1: %v", err)
	}
	v, err := d.ActiveCAVersion(ctx)
	if err != nil || v != 1 {
		t.Fatalf("ActiveCAVersion: v=%d err=%v", v, err)
	}
	if err := d.SetActiveCAVersion(ctx, 2); err != nil {
		t.Fatalf("SetActiveCAVersion 2: %v", err)
	}
	v, err = d.ActiveCAVersion(ctx)
	if err != nil || v != 2 {
		t.Fatalf("ActiveCAVersion after switch: v=%d err=%v", v, err)
	}
	if err := d.SetActiveCAVersion(ctx, 99); err == nil {
		t.Error("expected error setting active to non-existent version")
	}
}
