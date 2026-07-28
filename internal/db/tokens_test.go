package db

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// seedReenrollPeer inserts an inbound peer with groups+allowed {infra} and a
// pre-existing key/cert/pull token, mirroring an already-enrolled fleet member.
func seedReenrollPeer(t *testing.T, d *DB, name string) {
	t.Helper()
	ctx := context.Background()
	if err := d.InsertPeer(ctx, name, 7, "SHA256:old", []byte("ssh-ed25519 OLDKEY"), "alice", true, "old-pull"); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	if err := d.SetPeerCert(ctx, name, []byte("OLDCERT"), 7); err != nil {
		t.Fatalf("SetPeerCert: %v", err)
	}
	for _, g := range []string{"infra", "db"} {
		if err := d.EnsureGroup(ctx, g); err != nil {
			t.Fatalf("EnsureGroup: %v", err)
		}
	}
	if err := d.SetPeerGroups(ctx, name, []string{"infra"}); err != nil {
		t.Fatalf("SetPeerGroups: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, name, []string{"infra"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups: %v", err)
	}
}

func insertStagedToken(t *testing.T, d *DB, tok, peer, groupsCSV string, staged StagedReenroll) {
	t.Helper()
	if err := d.WithTx(context.Background(), func(tx *Tx) error {
		return tx.InsertReenrollToken(context.Background(), tok, peer, groupsCSV, "alice", []byte("tarball"), staged)
	}); err != nil {
		t.Fatalf("InsertReenrollToken: %v", err)
	}
}

func sampleStaged() StagedReenroll {
	return StagedReenroll{
		AuthorizedKey: []byte("ssh-ed25519 NEWKEY"),
		Fingerprint:   "SHA256:new",
		Serial:        42,
		Cert:          []byte("NEWCERT"),
		PullToken:     "new-pull",
		Inbound:       true,
	}
}

// TestConsumeStagedTokenCommitsToPeerRow: redeeming a re-enroll token commits
// every staged field to the peer row and bumps fleet_rev, atomically with the
// consume itself.
func TestConsumeStagedTokenCommitsToPeerRow(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	seedReenrollPeer(t, d, "vm1")
	staged := sampleStaged()
	staged.Address = "10.9.9.9"
	insertStagedToken(t, d, "tok-re", "vm1", "infra,db", staged)

	// The mint itself must leave the peer row untouched.
	before, err := d.GetPeer(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if before.Serial != 7 || string(before.AuthorizedKey) != "ssh-ed25519 OLDKEY" || before.PullToken != "old-pull" {
		t.Fatalf("peer row changed by staged insert: %+v", before)
	}

	peerName, groupsCSV, targetUser, tarball, err := d.ConsumeToken(ctx, "tok-re")
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if peerName != "vm1" || groupsCSV != "infra,db" || targetUser != "alice" || string(tarball) != "tarball" {
		t.Errorf("consume returned (%q,%q,%q,%q)", peerName, groupsCSV, targetUser, tarball)
	}

	p, err := d.GetPeer(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeer after consume: %v", err)
	}
	if string(p.AuthorizedKey) != "ssh-ed25519 NEWKEY" || p.Fingerprint != "SHA256:new" ||
		p.Serial != 42 || !bytes.Equal(p.Cert, []byte("NEWCERT")) || p.PullToken != "new-pull" ||
		!p.Inbound || p.Address != "10.9.9.9" {
		t.Errorf("staged material not committed: %+v", p)
	}
	groups, err := d.GetPeerGroups(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeerGroups: %v", err)
	}
	if !reflect.DeepEqual(groups, []string{"db", "infra"}) && !reflect.DeepEqual(groups, []string{"infra", "db"}) {
		t.Errorf("groups = %v, want {infra,db}", groups)
	}
	// Inbound->inbound re-enroll preserves the curated allowed set.
	allowed, err := d.GetPeerAllowedGroups(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	if !reflect.DeepEqual(allowed, []string{"infra"}) {
		t.Errorf("allowed = %v, want [infra] (preserved)", allowed)
	}
	rev, err := d.FleetRev(ctx)
	if err != nil {
		t.Fatalf("FleetRev: %v", err)
	}
	if rev != 1 {
		t.Errorf("fleet rev = %d, want 1 (bumped once at commit)", rev)
	}
}

// TestConsumeStagedTokenClearsStagedMaterial: after redemption the token row
// keeps neither the tarball nor any staged blob.
func TestConsumeStagedTokenClearsStagedMaterial(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	seedReenrollPeer(t, d, "vm1")
	insertStagedToken(t, d, "tok-re", "vm1", "infra", sampleStaged())

	if _, _, _, _, err := d.ConsumeToken(ctx, "tok-re"); err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}

	var tarball, stagedKey, stagedCert []byte
	var fp, pull, addr string
	var serial int64
	if err := d.sql.QueryRowContext(ctx,
		`SELECT tarball, staged_authorized_key, staged_cert, staged_fingerprint, staged_pull_token, staged_address, staged_serial
		 FROM tokens WHERE token = 'tok-re'`).
		Scan(&tarball, &stagedKey, &stagedCert, &fp, &pull, &addr, &serial); err != nil {
		t.Fatalf("select token row: %v", err)
	}
	if tarball != nil || stagedKey != nil || stagedCert != nil || fp != "" || pull != "" || addr != "" || serial != 0 {
		t.Errorf("staged material lingers: tarball=%v key=%v cert=%v fp=%q pull=%q addr=%q serial=%d",
			tarball, stagedKey, stagedCert, fp, pull, addr, serial)
	}

	if _, _, _, _, err := d.ConsumeToken(ctx, "tok-re"); !errors.Is(err, ErrTokenAlreadyConsumed) {
		t.Errorf("second consume err = %v, want ErrTokenAlreadyConsumed", err)
	}
}

// TestConsumeStagedTokenInboundToClient: a staged inbound=false commit flips
// the peer to client and clears its allowed-inbound rows.
func TestConsumeStagedTokenInboundToClient(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	seedReenrollPeer(t, d, "vm1")
	staged := sampleStaged()
	staged.Inbound = false
	insertStagedToken(t, d, "tok-cl", "vm1", "infra", staged)

	if _, _, _, _, err := d.ConsumeToken(ctx, "tok-cl"); err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	p, err := d.GetPeer(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.Inbound {
		t.Error("Inbound = true, want false after client re-enroll commit")
	}
	allowed, err := d.GetPeerAllowedGroups(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	if len(allowed) != 0 {
		t.Errorf("allowed = %v, want none for a client peer", allowed)
	}
}

// TestConsumeStagedTokenClientToInbound: a client peer re-enrolled inbound gets
// symmetric allowed rows seeded from the token's groups, like a fresh enroll.
func TestConsumeStagedTokenClientToInbound(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	if err := d.InsertPeer(ctx, "laptop", 7, "SHA256:old", []byte("ssh-ed25519 OLDKEY"), "alice", false, "old-pull"); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	if err := d.EnsureGroup(ctx, "infra"); err != nil {
		t.Fatalf("EnsureGroup: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "laptop", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerGroups: %v", err)
	}
	insertStagedToken(t, d, "tok-in", "laptop", "infra", sampleStaged())

	if _, _, _, _, err := d.ConsumeToken(ctx, "tok-in"); err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	p, err := d.GetPeer(ctx, "laptop")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if !p.Inbound {
		t.Error("Inbound = false, want true after inbound re-enroll commit")
	}
	allowed, err := d.GetPeerAllowedGroups(ctx, "laptop")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	if !reflect.DeepEqual(allowed, []string{"infra"}) {
		t.Errorf("allowed = %v, want [infra] (seeded symmetric)", allowed)
	}
}

// TestConsumeStagedTokenExplicitAllowed: a staged AllowedSet list overrides the
// preserve-current default at commit (the TUI form's allowed picker), and an
// explicit EMPTY list clears the allowed set.
func TestConsumeStagedTokenExplicitAllowed(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	seedReenrollPeer(t, d, "vm1")

	staged := sampleStaged()
	staged.Allowed = []string{"db"}
	staged.AllowedSet = true
	insertStagedToken(t, d, "tok-alw", "vm1", "infra", staged)
	if _, _, _, _, err := d.ConsumeToken(ctx, "tok-alw"); err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	allowed, err := d.GetPeerAllowedGroups(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	if !reflect.DeepEqual(allowed, []string{"db"}) {
		t.Errorf("allowed = %v, want [db] (explicit choice wins over preserve)", allowed)
	}

	empty := sampleStaged()
	empty.AllowedSet = true
	insertStagedToken(t, d, "tok-alw0", "vm1", "infra", empty)
	if _, _, _, _, err := d.ConsumeToken(ctx, "tok-alw0"); err != nil {
		t.Fatalf("ConsumeToken empty allowed: %v", err)
	}
	allowed, err = d.GetPeerAllowedGroups(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	if len(allowed) != 0 {
		t.Errorf("allowed = %v, want none after an explicit empty set", allowed)
	}
}

// TestConsumeStagedTokenExplicitAllowedDeletedGroup: strictness covers the
// explicit allowed list too — a vanished group fails the consume cleanly.
func TestConsumeStagedTokenExplicitAllowedDeletedGroup(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	seedReenrollPeer(t, d, "vm1")
	if err := d.EnsureGroup(ctx, "tmpa"); err != nil {
		t.Fatalf("EnsureGroup tmpa: %v", err)
	}
	staged := sampleStaged()
	staged.Allowed = []string{"tmpa"}
	staged.AllowedSet = true
	insertStagedToken(t, d, "tok-alwx", "vm1", "infra", staged)
	if err := d.DeleteGroup(ctx, "tmpa"); err != nil {
		t.Fatalf("DeleteGroup tmpa: %v", err)
	}

	_, _, _, _, err := d.ConsumeToken(ctx, "tok-alwx")
	if err == nil || !strings.Contains(err.Error(), `group "tmpa" no longer exists`) {
		t.Fatalf("err = %v, want tmpa-missing failure", err)
	}
	if exists, gerr := d.GroupExists(ctx, "tmpa"); gerr != nil || exists {
		t.Errorf("group tmpa resurrected (exists=%v err=%v)", exists, gerr)
	}
	var consumed int
	if err := d.sql.QueryRowContext(ctx, `SELECT consumed FROM tokens WHERE token='tok-alwx'`).Scan(&consumed); err != nil || consumed != 0 {
		t.Errorf("token must stay unconsumed (consumed=%d err=%v)", consumed, err)
	}
}

// TestConsumeStagedTokenEmptyAddressKeepsCurrent: an empty staged address means
// "leave the recorded dial address alone".
func TestConsumeStagedTokenEmptyAddressKeepsCurrent(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	seedReenrollPeer(t, d, "vm1")
	if err := d.SetPeerAddress(ctx, "vm1", "10.0.0.5"); err != nil {
		t.Fatalf("SetPeerAddress: %v", err)
	}
	insertStagedToken(t, d, "tok-addr", "vm1", "infra", sampleStaged())

	if _, _, _, _, err := d.ConsumeToken(ctx, "tok-addr"); err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	p, err := d.GetPeer(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.Address != "10.0.0.5" {
		t.Errorf("Address = %q, want 10.0.0.5 (kept)", p.Address)
	}
}

// TestConsumeStagedTokenCommitFailureIsAtomic injects a peer_groups failure via
// a trigger: the consume must roll back entirely — token still redeemable,
// peer row byte-identical, fleet_rev untouched — so the one-liner is retryable.
func TestConsumeStagedTokenCommitFailureIsAtomic(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	seedReenrollPeer(t, d, "vm1")
	insertStagedToken(t, d, "tok-fail", "vm1", "infra", sampleStaged())

	if _, err := d.sql.ExecContext(ctx,
		`CREATE TRIGGER block_pg BEFORE INSERT ON peer_groups BEGIN SELECT RAISE(ABORT, 'pg blocked'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	if _, _, _, _, err := d.ConsumeToken(ctx, "tok-fail"); err == nil {
		t.Fatal("expected consume to fail via trigger")
	}

	p, err := d.GetPeer(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if string(p.AuthorizedKey) != "ssh-ed25519 OLDKEY" || p.Serial != 7 || p.PullToken != "old-pull" {
		t.Errorf("peer row must be unchanged after rolled-back commit: %+v", p)
	}
	rev, err := d.FleetRev(ctx)
	if err != nil {
		t.Fatalf("FleetRev: %v", err)
	}
	if rev != 0 {
		t.Errorf("fleet rev = %d, want 0 after rollback", rev)
	}

	// The token must still be redeemable once the obstacle is gone (retry path).
	if _, err := d.sql.ExecContext(ctx, `DROP TRIGGER block_pg`); err != nil {
		t.Fatalf("drop trigger: %v", err)
	}
	if _, _, _, tarball, err := d.ConsumeToken(ctx, "tok-fail"); err != nil || string(tarball) != "tarball" {
		t.Fatalf("retry consume: err=%v tarball=%q (token must have stayed unconsumed)", err, tarball)
	}
}

// snapshotPeerState captures the peer row + membership rows for byte-identical
// comparison around a failed redemption.
func snapshotPeerState(t *testing.T, d *DB, name string) string {
	t.Helper()
	ctx := context.Background()
	p, err := d.GetPeer(ctx, name)
	if err != nil {
		t.Fatalf("GetPeer %s: %v", name, err)
	}
	groups, err := d.GetPeerGroups(ctx, name)
	if err != nil {
		t.Fatalf("GetPeerGroups %s: %v", name, err)
	}
	allowed, err := d.GetPeerAllowedGroups(ctx, name)
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups %s: %v", name, err)
	}
	return fmt.Sprintf("%+v|groups=%v|allowed=%v", *p, groups, allowed)
}

// TestConsumeStagedTokenDeletedGroupFailsCleanly is the REAL (non-injected)
// drift case: a group named by the staged token is deleted between mint and
// redemption. The consume must fail without resurrecting the group — token
// still unconsumed, peer state byte-identical, fleet_rev unmoved — and become
// redeemable again once the obstacle is resolved.
func TestConsumeStagedTokenDeletedGroupFailsCleanly(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	seedReenrollPeer(t, d, "vm1")
	if err := d.EnsureGroup(ctx, "tmpg"); err != nil {
		t.Fatalf("EnsureGroup tmpg: %v", err)
	}
	insertStagedToken(t, d, "tok-drift", "vm1", "infra,tmpg", sampleStaged())
	if err := d.DeleteGroup(ctx, "tmpg"); err != nil {
		t.Fatalf("DeleteGroup tmpg: %v", err)
	}
	before := snapshotPeerState(t, d, "vm1")

	_, _, _, _, err := d.ConsumeToken(ctx, "tok-drift")
	if err == nil {
		t.Fatal("expected consume to fail for a deleted group")
	}
	if !strings.Contains(err.Error(), `group "tmpg" no longer exists`) {
		t.Errorf("err = %q, want it to name the missing group tmpg", err)
	}

	if exists, gerr := d.GroupExists(ctx, "tmpg"); gerr != nil || exists {
		t.Errorf("group tmpg resurrected by the failed redemption (exists=%v err=%v)", exists, gerr)
	}
	if after := snapshotPeerState(t, d, "vm1"); after != before {
		t.Errorf("peer state changed by failed redemption:\nbefore: %s\nafter:  %s", before, after)
	}
	rev, err := d.FleetRev(ctx)
	if err != nil {
		t.Fatalf("FleetRev: %v", err)
	}
	if rev != 0 {
		t.Errorf("fleet rev = %d, want 0 after rolled-back redemption", rev)
	}

	// Once the group exists again the SAME token redeems (retryable).
	if err := d.EnsureGroup(ctx, "tmpg"); err != nil {
		t.Fatalf("re-create tmpg: %v", err)
	}
	if _, _, _, tarball, err := d.ConsumeToken(ctx, "tok-drift"); err != nil || string(tarball) != "tarball" {
		t.Fatalf("retry consume after fixing the group: err=%v tarball=%q", err, tarball)
	}
}

// TestConsumeStagedTokenRenamedGroupFailsCleanly: the rename analogue — the
// mint-time name must not be resurrected.
func TestConsumeStagedTokenRenamedGroupFailsCleanly(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	seedReenrollPeer(t, d, "vm1")
	if err := d.EnsureGroup(ctx, "oldg"); err != nil {
		t.Fatalf("EnsureGroup oldg: %v", err)
	}
	insertStagedToken(t, d, "tok-ren", "vm1", "oldg", sampleStaged())
	if err := d.RenameGroup(ctx, "oldg", "newg"); err != nil {
		t.Fatalf("RenameGroup: %v", err)
	}

	_, _, _, _, err := d.ConsumeToken(ctx, "tok-ren")
	if err == nil {
		t.Fatal("expected consume to fail for a renamed group")
	}
	if !strings.Contains(err.Error(), `group "oldg" no longer exists`) {
		t.Errorf("err = %q, want it to name the stale group oldg", err)
	}
	if exists, gerr := d.GroupExists(ctx, "oldg"); gerr != nil || exists {
		t.Errorf("old group name resurrected by the failed redemption (exists=%v err=%v)", exists, gerr)
	}
	var consumed int
	if err := d.sql.QueryRowContext(ctx, `SELECT consumed FROM tokens WHERE token='tok-ren'`).Scan(&consumed); err != nil || consumed != 0 {
		t.Errorf("token must stay unconsumed (consumed=%d err=%v)", consumed, err)
	}
}

// TestConsumeStagedTokenRevokedPeerRefused: a peer revoked between mint and
// redemption (the failed revoke --rekey window) must not be reconfigured by a
// live pre-revoke token.
func TestConsumeStagedTokenRevokedPeerRefused(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	seedReenrollPeer(t, d, "vm1")
	insertStagedToken(t, d, "tok-rev", "vm1", "infra", sampleStaged())
	if err := d.SetPeerRevoked(ctx, "vm1"); err != nil {
		t.Fatalf("SetPeerRevoked: %v", err)
	}
	before := snapshotPeerState(t, d, "vm1")

	_, _, _, _, err := d.ConsumeToken(ctx, "tok-rev")
	if err == nil {
		t.Fatal("expected consume to be refused for a revoked peer")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("err = %q, want a revoked refusal", err)
	}
	if after := snapshotPeerState(t, d, "vm1"); after != before {
		t.Errorf("revoked peer state changed:\nbefore: %s\nafter:  %s", before, after)
	}
	var consumed int
	if err := d.sql.QueryRowContext(ctx, `SELECT consumed FROM tokens WHERE token='tok-rev'`).Scan(&consumed); err != nil || consumed != 0 {
		t.Errorf("token must stay unconsumed (consumed=%d err=%v)", consumed, err)
	}
}

// TestDeleteUnconsumedPeerTokensSupersedes: a re-enroll mint deletes prior
// unconsumed tokens for the peer (they answer not-found afterwards) but leaves
// consumed history and other peers' tokens alone.
func TestDeleteUnconsumedPeerTokensSupersedes(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	if err := d.InsertToken(ctx, "tok-old", "vm1", "infra", "", []byte("tb1")); err != nil {
		t.Fatalf("InsertToken tok-old: %v", err)
	}
	if err := d.InsertToken(ctx, "tok-used", "vm1", "infra", "", []byte("tb2")); err != nil {
		t.Fatalf("InsertToken tok-used: %v", err)
	}
	if _, _, _, _, err := d.ConsumeToken(ctx, "tok-used"); err != nil {
		t.Fatalf("ConsumeToken tok-used: %v", err)
	}
	if err := d.InsertToken(ctx, "tok-other", "vm2", "infra", "", []byte("tb3")); err != nil {
		t.Fatalf("InsertToken tok-other: %v", err)
	}

	if err := d.WithTx(ctx, func(tx *Tx) error {
		return tx.DeleteUnconsumedPeerTokens(ctx, "vm1")
	}); err != nil {
		t.Fatalf("DeleteUnconsumedPeerTokens: %v", err)
	}

	if _, _, _, _, err := d.LookupToken(ctx, "tok-old"); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("superseded token lookup err = %v, want ErrTokenNotFound", err)
	}
	if _, _, _, consumed, err := d.LookupToken(ctx, "tok-used"); err != nil || !consumed {
		t.Errorf("consumed history must survive: err=%v consumed=%v", err, consumed)
	}
	if _, _, _, consumed, err := d.LookupToken(ctx, "tok-other"); err != nil || consumed {
		t.Errorf("other peer's token must survive: err=%v consumed=%v", err, consumed)
	}
}

// TestConsumePlainTokenDoesNotTouchPeers: consuming an ordinary (new-peer)
// token — NULL staged material — must not run the re-enroll commit.
func TestConsumePlainTokenDoesNotTouchPeers(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	seedReenrollPeer(t, d, "vm1")
	if err := d.InsertToken(ctx, "tok-plain", "vm1", "infra", "alice", []byte("tb")); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}
	if _, _, _, _, err := d.ConsumeToken(ctx, "tok-plain"); err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	p, err := d.GetPeer(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if string(p.AuthorizedKey) != "ssh-ed25519 OLDKEY" || p.Serial != 7 || p.PullToken != "old-pull" {
		t.Errorf("plain consume must not touch the peer row: %+v", p)
	}
	rev, err := d.FleetRev(ctx)
	if err != nil {
		t.Fatalf("FleetRev: %v", err)
	}
	if rev != 0 {
		t.Errorf("fleet rev = %d, want 0 (plain consume does not bump)", rev)
	}
}

// TestMigrateAddsStagedReenrollColumns: schema v9 adds the tokens.staged_*
// columns idempotently.
func TestMigrateAddsStagedReenrollColumns(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	cols, err := d.tableHasColumns(ctx, "tokens")
	if err != nil {
		t.Fatalf("tableHasColumns: %v", err)
	}
	for _, c := range []string{
		"staged_authorized_key", "staged_fingerprint", "staged_serial",
		"staged_cert", "staged_pull_token", "staged_inbound", "staged_address",
	} {
		if !cols[c] {
			t.Errorf("tokens.%s missing after migrate", c)
		}
	}
	// Re-running the migration must be a no-op.
	if err := d.migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

// TestConsumeStagedTokenPeerRowGone: a staged token whose peer row vanished
// (defensive; DeletePeer removes the token too) fails cleanly and rolls back.
func TestConsumeStagedTokenPeerRowGone(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	insertStagedToken(t, d, "tok-ghost", "ghost", "infra", sampleStaged())

	_, _, _, _, err := d.ConsumeToken(ctx, "tok-ghost")
	if err == nil {
		t.Fatal("expected error consuming staged token for a missing peer")
	}
	if !errors.Is(err, ErrPeerNotFound) {
		t.Errorf("err = %v, want ErrPeerNotFound in chain", err)
	}
	var consumed int
	if err := d.sql.QueryRowContext(ctx, `SELECT consumed FROM tokens WHERE token='tok-ghost'`).Scan(&consumed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			t.Fatal("token row vanished")
		}
		t.Fatalf("select: %v", err)
	}
	if consumed != 0 {
		t.Errorf("token consumed = %d, want 0 after rollback", consumed)
	}
}
