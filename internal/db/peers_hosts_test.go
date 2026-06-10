package db

import (
	"testing"
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
