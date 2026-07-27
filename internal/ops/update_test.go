package ops

import (
	"context"
	"strings"
	"testing"
)

// TestSelfGuardUpdatePeerRefusesSelf: a group edit aimed at the manager's own
// peer row is refused. The self cert carries the manager principal outside the
// group table, so re-signing it from DB groups would strip the principal every
// peer authorizes inbound manager SSH with — a fleet-wide push lockout.
func TestSelfGuardUpdatePeerRefusesSelf(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha")
	ctx := context.Background()
	seedSelfRow(t, dataDir, d, "mgr", nil)
	certBefore := storedCert(t, d, "mgr")
	revBefore := fleetRev(t, d)
	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	err := UpdatePeer(ctx, deps, "mgr", []string{"infra"}, "", "mgr")
	selfGuardCheckErr(t, err, "UpdatePeer")

	groups, err := d.GetPeerGroups(ctx, "mgr")
	if err != nil {
		t.Fatalf("GetPeerGroups: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("self groups = %v, want [] (refused edit must not land)", groups)
	}
	if got := storedCert(t, d, "mgr"); string(got) != string(certBefore) {
		t.Error("stored self cert was re-signed by a refused update")
	}
	assertManagerPrincipal(t, d, "mgr")
	if after := fleetRev(t, d); after != revBefore {
		t.Errorf("fleet_rev must be unchanged on refusal; %q -> %q", revBefore, after)
	}
	if len(dialer.dialedHosts) != 0 {
		t.Errorf("refused update must not dial; dialed=%v", dialer.dialedHosts)
	}
	if len(events) != 0 {
		t.Errorf("no event should be emitted on refusal; got %+v", events)
	}
}

// TestSelfGuardUpdatePeerEmptyHostnameFallsBackToOSHostname: the CLI passes no
// hostname, so the guard must resolve the self name from the OS.
func TestSelfGuardUpdatePeerEmptyHostnameFallsBackToOSHostname(t *testing.T) {
	selfGuardSetHostname(t, "mgr")
	dataDir, d := setupOpsEnv(t, "alpha")
	seedSelfRow(t, dataDir, d, "mgr", nil)
	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	err := UpdatePeer(context.Background(), deps, "mgr", []string{"infra"}, "", "")
	selfGuardCheckErr(t, err, "UpdatePeer (hostname fallback)")
	assertManagerPrincipal(t, d, "mgr")
	if len(dialer.dialedHosts) != 0 {
		t.Errorf("refused update must not dial; dialed=%v", dialer.dialedHosts)
	}
}

// TestUpdatePeerNonSelfKeepsWorking: the guard is scoped to the self row —
// an ordinary peer still gets its cert re-signed with name + groups.
func TestUpdatePeerNonSelfKeepsWorking(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha")
	ctx := context.Background()
	seedSelfRow(t, dataDir, d, "mgr", nil)
	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	if err := UpdatePeer(ctx, deps, "alpha", []string{"infra"}, "", "mgr"); err != nil {
		t.Fatalf("UpdatePeer alpha: %v", err)
	}
	if got := strings.Join(storedPrincipals(t, d, "alpha"), ","); got != "alpha,infra" {
		t.Errorf("alpha principals = %q, want \"alpha,infra\"", got)
	}
}
