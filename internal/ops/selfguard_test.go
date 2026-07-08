package ops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shudza/certhold/internal/db"
)

// selfGuardSetHostname pins the osHostname seam so the guard resolves the
// manager's self name deterministically, restoring the real resolver after.
func selfGuardSetHostname(t *testing.T, name string) {
	t.Helper()
	old := osHostname
	osHostname = func() (string, error) { return name, nil }
	t.Cleanup(func() { osHostname = old })
}

// selfGuardCheckErr asserts err is the self-guard refusal naming the self row.
func selfGuardCheckErr(t *testing.T, err error, op string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s against the self peer must error", op)
	}
	if !strings.Contains(err.Error(), `certhold's own peer "mgr"`) || !strings.Contains(err.Error(), "self row") {
		t.Errorf("%s error should name the manager's self row; got %q", op, err.Error())
	}
}

// selfGuardCheckRowIntact asserts the self row survived untouched: present and
// still inbound.
func selfGuardCheckRowIntact(t *testing.T, d *db.DB) {
	t.Helper()
	p, err := d.GetPeer(context.Background(), "mgr")
	if err != nil {
		t.Fatalf("self row must still exist: %v", err)
	}
	if !p.Inbound {
		t.Error("self row inbound flag must be unchanged (true)")
	}
}

func TestSelfGuardRemovePeerRefusesSelf(t *testing.T) {
	selfGuardSetHostname(t, "mgr")
	_, d := setupOpsEnv(t, "mgr", "alpha")
	var events []Event
	deps := noDialDeps(t, d, &events)

	err := RemovePeer(context.Background(), deps, "mgr")
	selfGuardCheckErr(t, err, "RemovePeer")
	selfGuardCheckRowIntact(t, d)
	if len(events) != 0 {
		t.Errorf("no event should be emitted on refusal; got %+v", events)
	}
}

func TestSelfGuardRemovePeerNonSelfUnaffected(t *testing.T) {
	selfGuardSetHostname(t, "mgr")
	_, d := setupOpsEnv(t, "mgr", "alpha")
	ctx := context.Background()
	var events []Event
	deps := noDialDeps(t, d, &events)

	if err := RemovePeer(ctx, deps, "alpha"); err != nil {
		t.Fatalf("RemovePeer non-self: %v", err)
	}
	if _, err := d.GetPeer(ctx, "alpha"); !errors.Is(err, db.ErrPeerNotFound) {
		t.Errorf("alpha should be deleted, got err=%v", err)
	}
	selfGuardCheckRowIntact(t, d)
}

func TestSelfGuardRevokeRefusesSelfDefault(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "mgr", "alpha")
	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	err := RevokePeer(context.Background(), deps, "mgr", "mgr", false)
	selfGuardCheckErr(t, err, "RevokePeer")
	selfGuardCheckRowIntact(t, d)
	if len(dialer.dialedHosts) != 0 {
		t.Errorf("self revoke must not dial; dialed=%v", dialer.dialedHosts)
	}
	if len(events) != 0 {
		t.Errorf("no event should be emitted on refusal; got %+v", events)
	}
}

func TestSelfGuardRevokeRefusesSelfRekey(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "mgr", "alpha")
	caPubBefore, err := os.ReadFile(filepath.Join(dataDir, "ca", "ca.pub"))
	if err != nil {
		t.Fatalf("read ca.pub: %v", err)
	}
	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	err = RevokePeer(context.Background(), deps, "mgr", "mgr", true)
	selfGuardCheckErr(t, err, "RevokePeer --rekey")
	selfGuardCheckRowIntact(t, d)
	if len(dialer.dialedHosts) != 0 {
		t.Errorf("self revoke --rekey must not dial; dialed=%v", dialer.dialedHosts)
	}
	caPubAfter, err := os.ReadFile(filepath.Join(dataDir, "ca", "ca.pub"))
	if err != nil {
		t.Fatalf("read ca.pub after: %v", err)
	}
	if string(caPubAfter) != string(caPubBefore) {
		t.Error("CA must not rotate on a refused self revoke")
	}
}

func TestSelfGuardRevokeEmptyHostnameFallsBackToOSHostname(t *testing.T) {
	selfGuardSetHostname(t, "mgr")
	dataDir, d := setupOpsEnv(t, "mgr")
	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	err := RevokePeer(context.Background(), deps, "mgr", "", false)
	selfGuardCheckErr(t, err, "RevokePeer (hostname fallback)")
	selfGuardCheckRowIntact(t, d)
	if len(dialer.dialedHosts) != 0 {
		t.Errorf("self revoke must not dial; dialed=%v", dialer.dialedHosts)
	}
}

func TestSelfGuardMakeClientRefusesSelf(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "mgr", "alpha")
	revBefore := fleetRev(t, d)
	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	err := MakeClient(context.Background(), deps, "mgr", "mgr")
	selfGuardCheckErr(t, err, "MakeClient")
	selfGuardCheckRowIntact(t, d)
	if len(dialer.dialedHosts) != 0 {
		t.Errorf("self make-client must not dial; dialed=%v", dialer.dialedHosts)
	}
	if after := fleetRev(t, d); after != revBefore {
		t.Errorf("fleet_rev must be unchanged on refusal; %q -> %q", revBefore, after)
	}
	if len(events) != 0 {
		t.Errorf("no event should be emitted on refusal; got %+v", events)
	}
}
