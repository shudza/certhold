package ops

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/shudza/certhold/internal/db"
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
