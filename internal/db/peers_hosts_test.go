package db

import (
	"testing"

	"github.com/shudza/certhold/internal/peerfiles"
)

// TestReachableHosts seeds a small fleet and walks the exclusion matrix:
// shared group included, no shared group / revoked / inbound=0 / self excluded,
// results ordered by name, and a peer reachable through two shared groups is
// not duplicated.
func TestReachableHosts(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)

	insert := func(name, targetUser string, inbound bool) {
		t.Helper()
		if err := d.InsertPeer(ctx, name, 1, "fp-"+name, []byte("k-"+name), targetUser, inbound, ""); err != nil {
			t.Fatalf("InsertPeer %s: %v", name, err)
		}
	}

	insert("client", "alice", false)
	insert("zeta", "root", true)
	insert("alpha", "deploy", true)
	insert("nogroup", "root", true)
	insert("dead", "root", true)
	insert("noinbound", "root", false)

	if err := d.SetPeerGroups(ctx, "client", []string{"infra", "db"}); err != nil {
		t.Fatalf("SetPeerGroups client: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "zeta", []string{"infra", "db"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups zeta: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "alpha", []string{"db"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups alpha: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "nogroup", []string{"web"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups nogroup: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "dead", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups dead: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "noinbound", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups noinbound: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "client", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups client: %v", err)
	}
	if err := d.SetPeerRevoked(ctx, "dead"); err != nil {
		t.Fatalf("SetPeerRevoked dead: %v", err)
	}
	if err := d.SetPeerAddress(ctx, "alpha", "10.0.0.5"); err != nil {
		t.Fatalf("SetPeerAddress alpha: %v", err)
	}

	hosts, err := d.ReachableHosts(ctx, "client")
	if err != nil {
		t.Fatalf("ReachableHosts: %v", err)
	}
	want := []ReachableHost{
		{Name: "alpha", Address: "10.0.0.5", TargetUser: "deploy"},
		{Name: "zeta", Address: "", TargetUser: "root"},
	}
	if len(hosts) != len(want) {
		t.Fatalf("ReachableHosts = %+v, want %+v", hosts, want)
	}
	for i := range want {
		if hosts[i] != want[i] {
			t.Errorf("hosts[%d] = %+v, want %+v", i, hosts[i], want[i])
		}
	}
}

func TestReachableHostsNoGroupsOrUnknownPeer(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)

	if err := d.InsertPeer(ctx, "lonely", 1, "fp", []byte("k"), "", true, ""); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}

	hosts, err := d.ReachableHosts(ctx, "lonely")
	if err != nil {
		t.Fatalf("ReachableHosts lonely: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("peer with no groups should reach nothing, got %+v", hosts)
	}

	hosts, err = d.ReachableHosts(ctx, "missing")
	if err != nil {
		t.Fatalf("ReachableHosts missing: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("unknown peer should reach nothing, got %+v", hosts)
	}
}

// TestReachableHostsManagerMember verifies that a peer which is a member of the
// manager group reaches ALL other inbound, non-revoked peers (including ones
// that do not explicitly allow the manager group, and the manager node itself),
// while revoked / no-inbound / self are still excluded. It also confirms the
// manager NODE — which init does not add to peer_groups "manager" — does not get
// the widened reach from this membership check.
func TestReachableHostsManagerMember(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)

	insert := func(name, targetUser string, inbound bool) {
		t.Helper()
		if err := d.InsertPeer(ctx, name, 1, "fp-"+name, []byte("k-"+name), targetUser, inbound, ""); err != nil {
			t.Fatalf("InsertPeer %s: %v", name, err)
		}
	}

	insert("manager", "root", true)
	insert("admin", "alice", true)
	insert("alpha", "deploy", true)
	insert("zeta", "root", true)
	insert("dead", "root", true)
	insert("noinbound", "root", false)

	if err := d.SetPeerGroups(ctx, "admin", []string{peerfiles.ManagerPrincipal}); err != nil {
		t.Fatalf("SetPeerGroups admin: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "manager", []string{peerfiles.ManagerPrincipal}); err != nil {
		t.Fatalf("SetPeerAllowedGroups manager: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "alpha", []string{"web"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups alpha: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "dead", []string{"web"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups dead: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "noinbound", []string{"web"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups noinbound: %v", err)
	}
	if err := d.SetPeerRevoked(ctx, "dead"); err != nil {
		t.Fatalf("SetPeerRevoked dead: %v", err)
	}

	hosts, err := d.ReachableHosts(ctx, "admin")
	if err != nil {
		t.Fatalf("ReachableHosts admin: %v", err)
	}
	want := []ReachableHost{
		{Name: "alpha", Address: "", TargetUser: "deploy"},
		{Name: "manager", Address: "", TargetUser: "root"},
		{Name: "zeta", Address: "", TargetUser: "root"},
	}
	if len(hosts) != len(want) {
		t.Fatalf("ReachableHosts admin = %+v, want %+v", hosts, want)
	}
	for i := range want {
		if hosts[i] != want[i] {
			t.Errorf("hosts[%d] = %+v, want %+v", i, hosts[i], want[i])
		}
	}

	// The manager NODE is not a peer_groups "manager" member (init bakes the
	// principal into its cert, not the group table), so it gets only normal
	// intersection reach — here, none.
	managerHosts, err := d.ReachableHosts(ctx, "manager")
	if err != nil {
		t.Fatalf("ReachableHosts manager: %v", err)
	}
	if len(managerHosts) != 0 {
		t.Errorf("manager node should not get widened reach, got %+v", managerHosts)
	}
}

// TestReachableHostsNonManagerUnchanged guards that the manager-member OR branch
// does not widen reachability for a normal (non-manager) peer: it must still see
// only peers that allow one of its own groups.
func TestReachableHostsNonManagerUnchanged(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)

	insert := func(name, targetUser string, inbound bool) {
		t.Helper()
		if err := d.InsertPeer(ctx, name, 1, "fp-"+name, []byte("k-"+name), targetUser, inbound, ""); err != nil {
			t.Fatalf("InsertPeer %s: %v", name, err)
		}
	}

	insert("web", "alice", true)
	insert("opener", "deploy", true)
	insert("closed", "root", true)
	insert("manager", "root", true)

	if err := d.SetPeerGroups(ctx, "web", []string{"web"}); err != nil {
		t.Fatalf("SetPeerGroups web: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "opener", []string{"web"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups opener: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "closed", []string{"db"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups closed: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "manager", []string{peerfiles.ManagerPrincipal}); err != nil {
		t.Fatalf("SetPeerAllowedGroups manager: %v", err)
	}

	hosts, err := d.ReachableHosts(ctx, "web")
	if err != nil {
		t.Fatalf("ReachableHosts web: %v", err)
	}
	want := []ReachableHost{
		{Name: "opener", Address: "", TargetUser: "deploy"},
	}
	if len(hosts) != len(want) {
		t.Fatalf("ReachableHosts web = %+v, want %+v", hosts, want)
	}
	if hosts[0] != want[0] {
		t.Errorf("hosts[0] = %+v, want %+v", hosts[0], want[0])
	}
}

// TestReachableHostsManagerMemberAlone verifies a manager-group member with no
// other peers reaches nothing and does not panic.
func TestReachableHostsManagerMemberAlone(t *testing.T) {
	ctx := t.Context()
	d := newTestDB(t)

	if err := d.InsertPeer(ctx, "solo", 1, "fp", []byte("k"), "root", true, ""); err != nil {
		t.Fatalf("InsertPeer solo: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "solo", []string{peerfiles.ManagerPrincipal}); err != nil {
		t.Fatalf("SetPeerGroups solo: %v", err)
	}

	hosts, err := d.ReachableHosts(ctx, "solo")
	if err != nil {
		t.Fatalf("ReachableHosts solo: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("manager member with no other peers should reach nothing, got %+v", hosts)
	}
}
