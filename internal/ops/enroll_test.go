package ops

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	_ "modernc.org/sqlite"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/peerfiles"
)

func TestMintEnrollCommitsPeerGroupsToken(t *testing.T) {
	dataDir, d := setupOpsEnv(t)
	ctx := context.Background()
	deps := Deps{DB: d, DataDir: dataDir}

	res, err := MintEnroll(ctx, deps, EnrollSpec{
		Name:    "vm1",
		Groups:  []string{"infra"},
		Allowed: []string{"infra"},
		User:    "alice",
		Address: "10.0.0.5",
		BaseURL: "https://certhold.home.lan",
	})
	if err != nil {
		t.Fatalf("MintEnroll: %v", err)
	}
	if res.PeerName != "vm1" {
		t.Errorf("PeerName = %q, want vm1", res.PeerName)
	}
	if res.Token == "" {
		t.Fatal("empty token")
	}
	if want := "curl -kfsSL https://certhold.home.lan/enroll/" + res.Token + ".sh | bash"; res.OneLiner != want {
		t.Errorf("OneLiner = %q, want %q", res.OneLiner, want)
	}

	p, err := d.GetPeer(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if !p.Inbound || p.PullToken == "" || len(p.Cert) == 0 || p.TargetUser != "alice" || p.Address != "10.0.0.5" {
		t.Errorf("peer row = %+v, want inbound, pull token, cert, alice, 10.0.0.5", p)
	}
	groups, err := d.GetPeerGroups(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeerGroups: %v", err)
	}
	if !reflect.DeepEqual(groups, []string{"infra"}) {
		t.Errorf("groups = %v, want [infra]", groups)
	}
	allowed, err := d.GetPeerAllowedGroups(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	if !reflect.DeepEqual(allowed, []string{"infra"}) {
		t.Errorf("allowed = %v, want [infra]", allowed)
	}
	rev, err := d.FleetRev(ctx)
	if err != nil {
		t.Fatalf("FleetRev: %v", err)
	}
	if rev != 1 {
		t.Errorf("fleet rev = %d, want 1", rev)
	}
	peerName, groupsCSV, targetUser, tarball, err := d.ConsumeToken(ctx, res.Token)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if peerName != "vm1" || groupsCSV != "infra" || targetUser != "alice" || len(tarball) == 0 {
		t.Errorf("token row = (%q, %q, %q, %d bytes), want vm1/infra/alice/tarball", peerName, groupsCSV, targetUser, len(tarball))
	}
}

func TestMintEnrollClientSkipsAllowedGroups(t *testing.T) {
	dataDir, d := setupOpsEnv(t)
	ctx := context.Background()
	deps := Deps{DB: d, DataDir: dataDir}

	res, err := MintEnroll(ctx, deps, EnrollSpec{
		Name:    "laptop",
		Groups:  []string{"infra"},
		Allowed: []string{"infra"},
		Client:  true,
		BaseURL: "https://certhold.home.lan",
	})
	if err != nil {
		t.Fatalf("MintEnroll: %v", err)
	}
	if res.Token == "" {
		t.Fatal("empty token")
	}
	p, err := d.GetPeer(ctx, "laptop")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.Inbound {
		t.Error("Inbound = true, want false for client enroll")
	}
	allowed, err := d.GetPeerAllowedGroups(ctx, "laptop")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	if len(allowed) != 0 {
		t.Errorf("allowed = %v, want none for client enroll", allowed)
	}
}

func TestMintEnrollRejectsInvalidAddressBeforeInsert(t *testing.T) {
	dataDir, d := setupOpsEnv(t)
	ctx := context.Background()
	deps := Deps{DB: d, DataDir: dataDir}

	_, err := MintEnroll(ctx, deps, EnrollSpec{
		Name:    "vm1",
		Groups:  []string{"infra"},
		Allowed: []string{"infra"},
		Address: "bad addr",
		BaseURL: "https://certhold.home.lan",
	})
	if err == nil {
		t.Fatal("expected invalid-address error")
	}
	if !strings.Contains(err.Error(), "invalid dial address") {
		t.Errorf("err = %q, want invalid-dial-address", err)
	}

	if _, gerr := d.GetPeer(ctx, "vm1"); !errors.Is(gerr, db.ErrPeerNotFound) {
		t.Errorf("peer vm1 must not be inserted; GetPeer err = %v, want ErrPeerNotFound", gerr)
	}
	rev, err := d.FleetRev(ctx)
	if err != nil {
		t.Fatalf("FleetRev: %v", err)
	}
	if rev != 0 {
		t.Errorf("fleet rev = %d, want 0 after rejected enroll", rev)
	}
}

// TestMintEnrollFailureRollsBackAll injects a tokens-insert failure via an
// sqlite trigger on the same file: the peer, groups and token rows must all
// roll back together.
func TestMintEnrollFailureRollsBackAll(t *testing.T) {
	dataDir, d := setupOpsEnv(t)
	ctx := context.Background()

	dbPath := filepath.Join(dataDir, "state.db")
	raw, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer raw.Close()
	if _, err := raw.ExecContext(ctx,
		`CREATE TRIGGER block_tokens BEFORE INSERT ON tokens BEGIN SELECT RAISE(ABORT, 'tokens blocked'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	deps := Deps{DB: d, DataDir: dataDir}
	_, err = MintEnroll(ctx, deps, EnrollSpec{
		Name:    "vm1",
		Groups:  []string{"infra"},
		Allowed: []string{"infra"},
		BaseURL: "https://certhold.home.lan",
	})
	if err == nil {
		t.Fatal("expected token insert failure")
	}
	if !strings.Contains(err.Error(), "insert token") {
		t.Errorf("err = %q, want it to mention 'insert token'", err)
	}

	if _, gerr := d.GetPeer(ctx, "vm1"); !errors.Is(gerr, db.ErrPeerNotFound) {
		t.Errorf("peer vm1 must be rolled back; GetPeer err = %v, want ErrPeerNotFound", gerr)
	}
	groups, err := d.GetPeerGroups(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeerGroups: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("peer groups = %v, want [] after rollback", groups)
	}
	rev, err := d.FleetRev(ctx)
	if err != nil {
		t.Fatalf("FleetRev: %v", err)
	}
	if rev != 0 {
		t.Errorf("fleet rev = %d, want 0 after rollback", rev)
	}
	var count int
	if err := raw.QueryRowContext(ctx, `SELECT COUNT(*) FROM tokens`).Scan(&count); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if count != 0 {
		t.Errorf("tokens rows = %d, want 0 after rollback", count)
	}
}

// TestReachableHostEntriesMatchesReachableHosts pins the pre-insert reachable
// computation to db.ReachableHosts' post-insert answer for the same peer.
func TestReachableHostEntriesMatchesReachableHosts(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peerA", "peerB")
	_ = dataDir
	ctx := context.Background()
	if err := d.SetPeerAddress(ctx, "peerA", "10.0.0.7"); err != nil {
		t.Fatalf("SetPeerAddress: %v", err)
	}
	if err := d.SetPeerRevoked(ctx, "peerB"); err != nil {
		t.Fatalf("SetPeerRevoked: %v", err)
	}
	if err := d.InsertPeer(ctx, "laptop", 1, "fp-l", []byte("k"), "alice", false, "tok"); err != nil {
		t.Fatalf("InsertPeer laptop: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "laptop", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups laptop: %v", err)
	}

	got, err := reachableHostEntries(ctx, d, "newpeer", []string{"infra"})
	if err != nil {
		t.Fatalf("reachableHostEntries: %v", err)
	}

	if err := d.InsertPeer(ctx, "newpeer", 1, "fp-n", []byte("k"), "", true, ""); err != nil {
		t.Fatalf("InsertPeer newpeer: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "newpeer", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerGroups newpeer: %v", err)
	}
	reachable, err := d.ReachableHosts(ctx, "newpeer")
	if err != nil {
		t.Fatalf("ReachableHosts: %v", err)
	}
	want := make([]string, 0, len(reachable))
	for _, h := range reachable {
		want = append(want, h.Name+"|"+h.Address+"|"+h.TargetUser)
	}
	have := make([]string, 0, len(got))
	for _, h := range got {
		have = append(have, h.Name+"|"+h.Address+"|"+h.User)
	}
	if !reflect.DeepEqual(have, want) {
		t.Errorf("reachableHostEntries = %v, want %v (db.ReachableHosts)", have, want)
	}
	if len(have) != 1 || !strings.HasPrefix(have[0], "peerA|10.0.0.7|") {
		t.Errorf("entries = %v, want only inbound non-revoked peerA", have)
	}
}

// setupManagerFixture builds the fleet from issue #171: A inbound allowing
// infra, B inbound allowing nothing, C revoked, D client-style (no inbound).
func setupManagerFixture(t *testing.T) (dataDir string, d *db.DB) {
	t.Helper()
	dataDir, d = setupOpsEnv(t, "peerA", "peerC")
	ctx := context.Background()
	if err := d.SetPeerAddress(ctx, "peerA", "10.0.0.1"); err != nil {
		t.Fatalf("SetPeerAddress peerA: %v", err)
	}
	if err := d.InsertPeer(ctx, "peerB", 1, "fp-b", []byte("k"), "root", true, ""); err != nil {
		t.Fatalf("InsertPeer peerB: %v", err)
	}
	if err := d.SetPeerAddress(ctx, "peerB", "10.0.0.2"); err != nil {
		t.Fatalf("SetPeerAddress peerB: %v", err)
	}
	if err := d.SetPeerAddress(ctx, "peerC", "10.0.0.3"); err != nil {
		t.Fatalf("SetPeerAddress peerC: %v", err)
	}
	if err := d.SetPeerRevoked(ctx, "peerC"); err != nil {
		t.Fatalf("SetPeerRevoked peerC: %v", err)
	}
	if err := d.InsertPeer(ctx, "peerD", 1, "fp-d", []byte("k"), "root", false, "tok-d"); err != nil {
		t.Fatalf("InsertPeer peerD: %v", err)
	}
	if err := d.EnsureGroup(ctx, peerfiles.ManagerPrincipal); err != nil {
		t.Fatalf("EnsureGroup manager: %v", err)
	}
	return dataDir, d
}

// TestMintEnrollManagerGroupReachesFleet: a peer enrolled directly into the
// manager group installs with Host aliases for every inbound non-revoked peer
// (the T151 manager branch of db.ReachableHosts), not just the peers that
// explicitly allow its groups.
func TestMintEnrollManagerGroupReachesFleet(t *testing.T) {
	dataDir, d := setupManagerFixture(t)
	ctx := context.Background()

	got, err := reachableHostEntries(ctx, d, "adminbox", []string{peerfiles.ManagerPrincipal})
	if err != nil {
		t.Fatalf("reachableHostEntries: %v", err)
	}
	want := []peerfiles.HostEntry{
		{Name: "peerA", Address: "10.0.0.1", User: "root"},
		{Name: "peerB", Address: "10.0.0.2", User: "root"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("reachableHostEntries = %+v, want %+v", got, want)
	}

	deps := Deps{DB: d, DataDir: dataDir}
	res, err := MintEnroll(ctx, deps, EnrollSpec{
		Name:    "adminbox",
		Groups:  []string{peerfiles.ManagerPrincipal},
		Allowed: []string{peerfiles.ManagerPrincipal},
		User:    "root",
		Address: "10.0.0.9",
		BaseURL: "https://certhold.home.lan",
	})
	if err != nil {
		t.Fatalf("MintEnroll: %v", err)
	}

	// Mirror property: the pre-insert computation must match db.ReachableHosts
	// for the same peer once inserted, field by field.
	reachable, err := d.ReachableHosts(ctx, "adminbox")
	if err != nil {
		t.Fatalf("ReachableHosts: %v", err)
	}
	if len(reachable) != len(got) {
		t.Fatalf("ReachableHosts = %+v, want %d entries matching %+v", reachable, len(got), got)
	}
	for i, h := range reachable {
		if got[i].Name != h.Name || got[i].Address != h.Address || got[i].User != h.TargetUser {
			t.Errorf("entry %d: mint-time %+v != db.ReachableHosts %+v", i, got[i], h)
		}
	}

	// The install tarball's ssh config carries the fleet Host aliases.
	_, _, _, tarball, err := d.ConsumeToken(ctx, res.Token)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	config := tarballFile(t, tarball, "config")
	for _, present := range []string{"Host peerA\n    HostName 10.0.0.1\n    User root\n", "Host peerB\n    HostName 10.0.0.2\n    User root\n"} {
		if !strings.Contains(config, present) {
			t.Errorf("config missing %q:\n%s", present, config)
		}
	}
	for _, absent := range []string{"Host peerC", "Host peerD", "Host adminbox"} {
		if strings.Contains(config, absent) {
			t.Errorf("config must not contain %q:\n%s", absent, config)
		}
	}
}

// TestReachableHostEntriesNonManagerIntersectionOnly: without the manager
// principal the mint-time host list stays the pure allowed-groups intersection.
func TestReachableHostEntriesNonManagerIntersectionOnly(t *testing.T) {
	_, d := setupManagerFixture(t)
	ctx := context.Background()

	got, err := reachableHostEntries(ctx, d, "newpeer", []string{"infra"})
	if err != nil {
		t.Fatalf("reachableHostEntries: %v", err)
	}
	want := []peerfiles.HostEntry{{Name: "peerA", Address: "10.0.0.1", User: "root"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("reachableHostEntries = %+v, want only peerA (%+v)", got, want)
	}
}

// snapshotPeer captures the full DB-visible state of a peer for byte-identical
// comparisons around a re-enroll mint.
func snapshotPeer(t *testing.T, d *db.DB, name string) string {
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

// TestMintReenrollLeavesPeerRowUntouched: minting a re-enroll for an existing
// peer stages everything on the token row — the peer's DB state is
// byte-identical afterwards and fleet_rev does not move.
func TestMintReenrollLeavesPeerRowUntouched(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peerA")
	ctx := context.Background()
	deps := Deps{DB: d, DataDir: dataDir}

	before := snapshotPeer(t, d, "peerA")
	revBefore, err := d.FleetRev(ctx)
	if err != nil {
		t.Fatalf("FleetRev: %v", err)
	}

	res, err := MintEnroll(ctx, deps, EnrollSpec{Name: "peerA", BaseURL: "https://certhold.home.lan"})
	if err != nil {
		t.Fatalf("MintEnroll re-enroll: %v", err)
	}
	if !res.Reenroll {
		t.Error("Reenroll = false, want true for an existing peer")
	}
	if res.Client {
		t.Error("Client = true, want false (peerA is inbound and no flag was set)")
	}

	if after := snapshotPeer(t, d, "peerA"); after != before {
		t.Errorf("peer state changed by re-enroll mint:\nbefore: %s\nafter:  %s", before, after)
	}
	revAfter, err := d.FleetRev(ctx)
	if err != nil {
		t.Fatalf("FleetRev: %v", err)
	}
	if revAfter != revBefore {
		t.Errorf("fleet rev moved at mint: %d -> %d (must only bump at redemption)", revBefore, revAfter)
	}
}

// TestMintReenrollDefaultsFromDB: with no flags, the staged token carries the
// peer's current groups and target user, and the tarball ships an inbound
// trust line built from the current allowed set.
func TestMintReenrollDefaultsFromDB(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peerA")
	ctx := context.Background()
	if err := d.EnsureGroup(ctx, "db"); err != nil {
		t.Fatalf("EnsureGroup: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "peerA", []string{"infra", "db"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups: %v", err)
	}
	deps := Deps{DB: d, DataDir: dataDir}

	res, err := MintEnroll(ctx, deps, EnrollSpec{Name: "peerA", BaseURL: "https://certhold.home.lan"})
	if err != nil {
		t.Fatalf("MintEnroll: %v", err)
	}

	peerName, groupsCSV, targetUser, tarball, err := d.ConsumeToken(ctx, res.Token)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if peerName != "peerA" || groupsCSV != "infra" || targetUser != "root" {
		t.Errorf("token = (%q,%q,%q), want peerA/infra/root (defaults from DB)", peerName, groupsCSV, targetUser)
	}
	ak := tarballFile(t, tarball, "ca_authorized_keys")
	if !strings.HasPrefix(ak, `cert-authority,principals="manager,db,infra" `) &&
		!strings.HasPrefix(ak, `cert-authority,principals="manager,infra,db" `) {
		t.Errorf("trust line principals should be the current allowed set: %q", ak)
	}
	if !hasTarballEntry(t, tarball, "certhold-cli") {
		t.Error("re-enroll bundle must ship certhold-cli (the motivating upgrade path)")
	}
}

// TestMintReenrollCommitAppliesStagedConfig: redeeming the re-enroll token
// commits the fresh key/cert/pull-token to the peer row (a full db-level
// mint->consume round trip through the real staged material).
func TestMintReenrollCommitAppliesStagedConfig(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peerA")
	ctx := context.Background()
	deps := Deps{DB: d, DataDir: dataDir}

	old, err := d.GetPeer(ctx, "peerA")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	res, err := MintEnroll(ctx, deps, EnrollSpec{Name: "peerA", BaseURL: "https://certhold.home.lan"})
	if err != nil {
		t.Fatalf("MintEnroll: %v", err)
	}
	if _, _, _, _, err := d.ConsumeToken(ctx, res.Token); err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	p, err := d.GetPeer(ctx, "peerA")
	if err != nil {
		t.Fatalf("GetPeer after consume: %v", err)
	}
	if bytes.Equal(p.AuthorizedKey, old.AuthorizedKey) {
		t.Error("peer key unchanged after redemption; re-enroll must mint a fresh keypair")
	}
	if p.Serial == old.Serial || len(p.Cert) == 0 || p.PullToken == old.PullToken || p.PullToken == "" {
		t.Errorf("staged material not committed: serial %d->%d, cert %d bytes, pull %q->%q",
			old.Serial, p.Serial, len(p.Cert), old.PullToken, p.PullToken)
	}
	cert, err := parseCert(p.Cert)
	if err != nil {
		t.Fatalf("parse committed cert: %v", err)
	}
	if !bytes.Equal(ssh.MarshalAuthorizedKey(cert.Key), p.AuthorizedKey) {
		t.Error("committed cert is not signed for the committed key")
	}
	rev, err := d.FleetRev(ctx)
	if err != nil {
		t.Fatalf("FleetRev: %v", err)
	}
	if rev != 1 {
		t.Errorf("fleet rev = %d, want 1 (bumped once, at redemption)", rev)
	}
}

// TestMintReenrollSupersedesPriorToken: a second re-enroll mint invalidates the
// first token (not-found afterwards) while the new one redeems normally.
func TestMintReenrollSupersedesPriorToken(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peerA")
	ctx := context.Background()
	deps := Deps{DB: d, DataDir: dataDir}

	first, err := MintEnroll(ctx, deps, EnrollSpec{Name: "peerA", BaseURL: "https://certhold.home.lan"})
	if err != nil {
		t.Fatalf("first MintEnroll: %v", err)
	}
	second, err := MintEnroll(ctx, deps, EnrollSpec{Name: "peerA", BaseURL: "https://certhold.home.lan"})
	if err != nil {
		t.Fatalf("second MintEnroll: %v", err)
	}

	if _, _, _, _, err := d.LookupToken(ctx, first.Token); !errors.Is(err, db.ErrTokenNotFound) {
		t.Errorf("superseded token lookup err = %v, want ErrTokenNotFound", err)
	}
	if _, _, _, tarball, err := d.ConsumeToken(ctx, second.Token); err != nil || len(tarball) == 0 {
		t.Fatalf("second token must redeem: err=%v tarball=%d bytes", err, len(tarball))
	}
}

// TestMintReenrollClientTransition: --client on a re-enroll stages a
// no-inbound bundle (ca_pub for the stale-line strip, no ca_authorized_keys)
// and an inbound=false commit.
func TestMintReenrollClientTransition(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peerA")
	ctx := context.Background()
	deps := Deps{DB: d, DataDir: dataDir}

	res, err := MintEnroll(ctx, deps, EnrollSpec{
		Name: "peerA", Client: true, ClientSet: true, BaseURL: "https://certhold.home.lan",
	})
	if err != nil {
		t.Fatalf("MintEnroll --client: %v", err)
	}
	if !res.Client {
		t.Error("Client = false, want true")
	}

	// Peer row still inbound until redemption.
	p, err := d.GetPeer(ctx, "peerA")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if !p.Inbound {
		t.Fatal("peer flipped to client at mint; must only flip at redemption")
	}

	_, _, _, tarball, err := d.ConsumeToken(ctx, res.Token)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if hasTarballEntry(t, tarball, "ca_authorized_keys") {
		t.Error("client re-enroll bundle must not ship ca_authorized_keys")
	}
	if !hasTarballEntry(t, tarball, "ca_pub") {
		t.Error("client re-enroll bundle must ship ca_pub for the stale trust-line strip")
	}
	p, err = d.GetPeer(ctx, "peerA")
	if err != nil {
		t.Fatalf("GetPeer after consume: %v", err)
	}
	if p.Inbound {
		t.Error("Inbound = true after client re-enroll redemption, want false")
	}
	allowed, err := d.GetPeerAllowedGroups(ctx, "peerA")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	if len(allowed) != 0 {
		t.Errorf("allowed = %v, want none after client transition", allowed)
	}
}

// TestMintReenrollInboundTransition: a client peer re-enrolled without flags
// stays client; with an explicit inbound choice it stages a trust-line-bearing
// bundle and flips inbound at redemption with symmetric allowed rows.
func TestMintReenrollInboundTransition(t *testing.T) {
	dataDir, d := setupOpsEnv(t)
	ctx := context.Background()
	if err := d.InsertPeer(ctx, "laptop", 5, "fp-l", []byte("ssh-ed25519 OLD"), "alice", false, "pull-old"); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "laptop", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerGroups: %v", err)
	}
	deps := Deps{DB: d, DataDir: dataDir}

	// Default: stays client.
	res, err := MintEnroll(ctx, deps, EnrollSpec{Name: "laptop", BaseURL: "https://certhold.home.lan"})
	if err != nil {
		t.Fatalf("MintEnroll default: %v", err)
	}
	if !res.Client {
		t.Error("re-enroll of a client peer without flags must stay client")
	}

	// Explicit inbound choice flips it.
	res, err = MintEnroll(ctx, deps, EnrollSpec{
		Name: "laptop", Client: false, ClientSet: true, BaseURL: "https://certhold.home.lan",
	})
	if err != nil {
		t.Fatalf("MintEnroll inbound: %v", err)
	}
	if res.Client {
		t.Error("Client = true, want false for an explicit inbound re-enroll")
	}
	_, _, _, tarball, err := d.ConsumeToken(ctx, res.Token)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	ak := tarballFile(t, tarball, "ca_authorized_keys")
	if !strings.HasPrefix(ak, `cert-authority,principals="manager,infra" `) {
		t.Errorf("trust line = %q, want manager,infra (symmetric with groups)", ak)
	}
	p, err := d.GetPeer(ctx, "laptop")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if !p.Inbound {
		t.Error("Inbound = false after inbound re-enroll redemption, want true")
	}
	allowed, err := d.GetPeerAllowedGroups(ctx, "laptop")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	if !reflect.DeepEqual(allowed, []string{"infra"}) {
		t.Errorf("allowed = %v, want [infra]", allowed)
	}
}

// TestMintReenrollAllowedSetHonored: an explicit Allowed choice (the TUI
// form's picker) is staged and applied at redemption, overriding the
// preserve-current default, and the tarball trust line mirrors it.
func TestMintReenrollAllowedSetHonored(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peerA")
	ctx := context.Background()
	if err := d.EnsureGroup(ctx, "db"); err != nil {
		t.Fatalf("EnsureGroup: %v", err)
	}
	deps := Deps{DB: d, DataDir: dataDir}

	res, err := MintEnroll(ctx, deps, EnrollSpec{
		Name:       "peerA",
		Allowed:    []string{"db"},
		AllowedSet: true,
		BaseURL:    "https://certhold.home.lan",
	})
	if err != nil {
		t.Fatalf("MintEnroll AllowedSet: %v", err)
	}

	// Unredeemed: DB allowed still the current set.
	allowed, err := d.GetPeerAllowedGroups(ctx, "peerA")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	if !reflect.DeepEqual(allowed, []string{"infra"}) {
		t.Fatalf("allowed changed at mint: %v", allowed)
	}

	_, _, _, tarball, err := d.ConsumeToken(ctx, res.Token)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	ak := tarballFile(t, tarball, "ca_authorized_keys")
	if !strings.HasPrefix(ak, `cert-authority,principals="manager,db" `) {
		t.Errorf("trust line = %q, want manager,db (the explicit allowed set)", ak)
	}
	allowed, err = d.GetPeerAllowedGroups(ctx, "peerA")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups after commit: %v", err)
	}
	if !reflect.DeepEqual(allowed, []string{"db"}) {
		t.Errorf("allowed after commit = %v, want [db]", allowed)
	}
}

// TestMintReenrollAllowedSetValidatesGroups: an explicit allowed list is
// group-exists validated at mint like the membership list.
func TestMintReenrollAllowedSetValidatesGroups(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peerA")
	ctx := context.Background()
	deps := Deps{DB: d, DataDir: dataDir}

	_, err := MintEnroll(ctx, deps, EnrollSpec{
		Name:       "peerA",
		Allowed:    []string{"nope"},
		AllowedSet: true,
		BaseURL:    "https://certhold.home.lan",
	})
	if err == nil || !strings.Contains(err.Error(), `group "nope" does not exist`) {
		t.Fatalf("err = %v, want group-does-not-exist for the allowed list", err)
	}
}

// TestMintReenrollGroupEditPushUsesOldKey is the unredeemed-one-liner safety
// property end to end: after a re-enroll mint, a group edit + push cycle still
// re-signs and pushes a cert for the peer's OLD key, so the live peer (which
// never ran the one-liner) keeps working.
func TestMintReenrollGroupEditPushUsesOldKey(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peerA")
	ctx := context.Background()

	old, err := d.GetPeer(ctx, "peerA")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}

	mintDeps := Deps{DB: d, DataDir: dataDir}
	if _, err := MintEnroll(ctx, mintDeps, EnrollSpec{Name: "peerA", BaseURL: "https://certhold.home.lan"}); err != nil {
		t.Fatalf("MintEnroll re-enroll: %v", err)
	}

	dialer := &fakeDialer{readData: map[string][]byte{
		"/root/.ssh/authorized_keys": opsCALine(t, dataDir, "manager", "infra"),
	}}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)
	if err := UpdatePeer(ctx, deps, "peerA", []string{"infra"}, "", "mgr"); err != nil {
		t.Fatalf("UpdatePeer after re-enroll mint: %v", err)
	}

	instanceKey, err := EnsureInstanceKey(ctx, d)
	if err != nil {
		t.Fatalf("EnsureInstanceKey: %v", err)
	}
	certPath := PeerCertRemotePath(old, instanceKey)
	var pushedCert []byte
	for _, c := range dialer.snapshot() {
		if c.op == "write" && c.path == certPath {
			pushedCert = c.content
		}
	}
	if pushedCert == nil {
		t.Fatalf("no cert write to %s in push calls: %+v", certPath, dialer.snapshot())
	}
	cert, err := parseCert(pushedCert)
	if err != nil {
		t.Fatalf("parse pushed cert: %v", err)
	}
	if !bytes.Equal(ssh.MarshalAuthorizedKey(cert.Key), old.AuthorizedKey) {
		t.Error("pushed cert is not signed for the peer's OLD key; the unredeemed re-enroll leaked into the push path")
	}
}

// TestMintReenrollRefusesSelf: the manager's own row cannot be re-enrolled.
func TestMintReenrollRefusesSelf(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "mgrhost")
	ctx := context.Background()
	selfGuardSetHostname(t, "mgrhost")
	deps := Deps{DB: d, DataDir: dataDir}

	_, err := MintEnroll(ctx, deps, EnrollSpec{Name: "mgrhost", BaseURL: "https://certhold.home.lan"})
	if err == nil {
		t.Fatal("expected self-guard refusal")
	}
	if !strings.Contains(err.Error(), "refusing to re-enroll") || !strings.Contains(err.Error(), "self row") {
		t.Errorf("err = %q, want the self-guard refusal", err)
	}
}

// TestMintReenrollRefusesSelfByCert: the self row is refused even when it was
// named via `init --hostname` and differs from os.Hostname() — the self cert
// on disk (KeyID = manager name) is the second guard signal.
func TestMintReenrollRefusesSelfByCert(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "namedmgr")
	ctx := context.Background()
	selfGuardSetHostname(t, "some-other-host")

	caObj, err := ca.LoadWithPassphrase(filepath.Join(dataDir, "ca"), nil)
	if err != nil {
		t.Fatalf("load ca: %v", err)
	}
	_, _, sshPub, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	certBytes, _, err := caObj.SignCert(ca.SignOptions{
		Pubkey: sshPub, KeyID: "namedmgr", Principals: []string{"namedmgr", peerfiles.ManagerPrincipal},
	})
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	key := mustInstanceKey(t, d)
	selfSSH := filepath.Join(dataDir, "self", "home", "alice", ".ssh")
	if err := os.MkdirAll(selfSSH, 0o700); err != nil {
		t.Fatalf("mkdir self: %v", err)
	}
	if err := os.WriteFile(filepath.Join(selfSSH, peerfiles.V2CertFileName(key)), certBytes, 0o644); err != nil {
		t.Fatalf("write self cert: %v", err)
	}

	deps := Deps{DB: d, DataDir: dataDir}
	_, err = MintEnroll(ctx, deps, EnrollSpec{Name: "namedmgr", BaseURL: "https://certhold.home.lan"})
	if err == nil {
		t.Fatal("expected self-guard refusal via the self cert")
	}
	if !strings.Contains(err.Error(), "refusing to re-enroll") || !strings.Contains(err.Error(), "self row") {
		t.Errorf("err = %q, want the self-guard refusal", err)
	}
}

// TestMintReenrollRefusesRevoked: a revoked row is not silently resurrected.
func TestMintReenrollRefusesRevoked(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peerA")
	ctx := context.Background()
	if err := d.SetPeerRevoked(ctx, "peerA"); err != nil {
		t.Fatalf("SetPeerRevoked: %v", err)
	}
	deps := Deps{DB: d, DataDir: dataDir}

	_, err := MintEnroll(ctx, deps, EnrollSpec{Name: "peerA", BaseURL: "https://certhold.home.lan"})
	if err == nil {
		t.Fatal("expected revoked refusal")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("err = %q, want revoked refusal", err)
	}
}

// TestMintEnrollNewNameRequiresGroups: the new-name path still demands
// --groups.
func TestMintEnrollNewNameRequiresGroups(t *testing.T) {
	dataDir, d := setupOpsEnv(t)
	ctx := context.Background()
	deps := Deps{DB: d, DataDir: dataDir}

	_, err := MintEnroll(ctx, deps, EnrollSpec{Name: "brandnew", BaseURL: "https://certhold.home.lan"})
	if err == nil {
		t.Fatal("expected groups-required error")
	}
	if !strings.Contains(err.Error(), "--groups is required") {
		t.Errorf("err = %q, want --groups-required", err)
	}
}

// TestMintReenrollManagerGroup: T157 semantics survive the re-enroll path — an
// explicit --groups manager mints a cert carrying the manager principal.
func TestMintReenrollManagerGroup(t *testing.T) {
	dataDir, d := setupManagerFixture(t)
	ctx := context.Background()
	deps := Deps{DB: d, DataDir: dataDir}

	res, err := MintEnroll(ctx, deps, EnrollSpec{
		Name:    "peerA",
		Groups:  []string{peerfiles.ManagerPrincipal},
		Allowed: []string{peerfiles.ManagerPrincipal},
		BaseURL: "https://certhold.home.lan",
	})
	if err != nil {
		t.Fatalf("MintEnroll --groups manager: %v", err)
	}
	_, groupsCSV, _, tarball, err := d.ConsumeToken(ctx, res.Token)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if groupsCSV != peerfiles.ManagerPrincipal {
		t.Errorf("groups CSV = %q, want manager", groupsCSV)
	}
	certRaw := tarballFile(t, tarball, "id_ed25519_"+mustInstanceKey(t, d)+"-cert.pub")
	cert, err := parseCert([]byte(certRaw))
	if err != nil {
		t.Fatalf("parse minted cert: %v", err)
	}
	if !slices.Contains(cert.ValidPrincipals, peerfiles.ManagerPrincipal) {
		t.Errorf("cert principals = %v, want manager included", cert.ValidPrincipals)
	}
}

// TestMintReenrollRejectsUnknownGroup: group-exists validation is unchanged on
// the re-enroll path.
func TestMintReenrollRejectsUnknownGroup(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peerA")
	ctx := context.Background()
	deps := Deps{DB: d, DataDir: dataDir}

	before := snapshotPeer(t, d, "peerA")
	_, err := MintEnroll(ctx, deps, EnrollSpec{
		Name: "peerA", Groups: []string{"nope"}, Allowed: []string{"nope"}, BaseURL: "https://certhold.home.lan",
	})
	if err == nil || !strings.Contains(err.Error(), `group "nope" does not exist`) {
		t.Fatalf("err = %v, want group-does-not-exist", err)
	}
	if after := snapshotPeer(t, d, "peerA"); after != before {
		t.Errorf("failed re-enroll mint changed peer state:\nbefore: %s\nafter:  %s", before, after)
	}
}

func mustInstanceKey(t *testing.T, d *db.DB) string {
	t.Helper()
	key, err := EnsureInstanceKey(context.Background(), d)
	if err != nil {
		t.Fatalf("EnsureInstanceKey: %v", err)
	}
	return key
}

func parseCert(b []byte) (*ssh.Certificate, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return nil, err
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("not a certificate: %T", pk)
	}
	return cert, nil
}

func hasTarballEntry(t *testing.T, tarball []byte, name string) bool {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return false
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}
		if hdr.Name == name {
			return true
		}
	}
}

// tarballFile extracts one file's contents from a gzip+tar archive.
func tarballFile(t *testing.T, tarball []byte, name string) string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}
		if hdr.Name == name {
			data, err := io.ReadAll(tr)
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			return string(data)
		}
	}
	t.Fatalf("tarball has no entry %q", name)
	return ""
}
