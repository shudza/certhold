package ops

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
)

func fleetRev(t *testing.T, d *db.DB) string {
	t.Helper()
	v, _, err := d.GetMeta(context.Background(), db.MetaFleetRev)
	if err != nil {
		t.Fatalf("GetMeta fleet_rev: %v", err)
	}
	return v
}

func TestSetPeerAddressUpdatesDBAndBumpsFleetRev(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha")
	ctx := context.Background()
	before := fleetRev(t, d)

	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	if err := SetPeerAddress(ctx, deps, "alpha", "10.0.0.5"); err != nil {
		t.Fatalf("SetPeerAddress: %v", err)
	}

	p, err := d.GetPeer(ctx, "alpha")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.Address != "10.0.0.5" {
		t.Errorf("address = %q, want 10.0.0.5", p.Address)
	}
	if after := fleetRev(t, d); after == before {
		t.Errorf("fleet_rev not bumped (still %q)", after)
	}
	if len(dialer.dialedHosts) != 0 {
		t.Errorf("SetPeerAddress must not dial; dialed=%v", dialer.dialedHosts)
	}
}

func TestSetPeerAddressClearsOnEmpty(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha")
	ctx := context.Background()
	if err := d.SetPeerAddress(ctx, "alpha", "10.0.0.5"); err != nil {
		t.Fatalf("seed address: %v", err)
	}

	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	if err := SetPeerAddress(ctx, deps, "alpha", ""); err != nil {
		t.Fatalf("SetPeerAddress clear: %v", err)
	}
	p, err := d.GetPeer(ctx, "alpha")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.Address != "" {
		t.Errorf("address = %q, want cleared", p.Address)
	}
}

func TestSetPeerAddressRejectsMissingPeer(t *testing.T) {
	dataDir, d := setupOpsEnv(t)
	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	err := SetPeerAddress(context.Background(), deps, "ghost", "10.0.0.9")
	if err == nil {
		t.Fatal("expected error for missing peer")
	}
	if !strings.Contains(err.Error(), "ghost") || !strings.Contains(err.Error(), "not found") {
		t.Errorf("err = %q, want peer-not-found", err)
	}
}

func TestSetPeerAddressRejectsInvalidWithoutStoring(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha")
	ctx := context.Background()
	if err := d.SetPeerAddress(ctx, "alpha", "10.0.0.5"); err != nil {
		t.Fatalf("seed address: %v", err)
	}
	before := fleetRev(t, d)

	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	for _, bad := range []string{"10.0.0.5 prod", "a\nProxyCommand evil", "host\t22", strings.Repeat("a", 300)} {
		err := SetPeerAddress(ctx, deps, "alpha", bad)
		if err == nil {
			t.Fatalf("SetPeerAddress(%q) = nil, want error", bad)
		}
		if !strings.Contains(err.Error(), "invalid dial address") {
			t.Errorf("SetPeerAddress(%q) err = %q, want invalid-dial-address", bad, err)
		}
	}

	p, err := d.GetPeer(ctx, "alpha")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.Address != "10.0.0.5" {
		t.Errorf("address = %q after rejected updates, want 10.0.0.5 untouched", p.Address)
	}
	if after := fleetRev(t, d); after != before {
		t.Errorf("fleet_rev bumped on rejected address (%q -> %q)", before, after)
	}
}

func TestMakeClientStripsCALineAndFlipsInbound(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha")
	ctx := context.Background()
	before := fleetRev(t, d)

	caLine := opsCALine(t, dataDir, "manager", "infra")
	existing := append([]byte("ssh-ed25519 AAAAkeepme operator@laptop\n"), caLine...)
	dialer := &fakeDialer{
		readData: map[string][]byte{"/root/.ssh/authorized_keys": existing},
	}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	if err := MakeClient(ctx, deps, "alpha", "mgr"); err != nil {
		t.Fatalf("MakeClient: %v", err)
	}

	p, err := d.GetPeer(ctx, "alpha")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.Inbound {
		t.Error("inbound must be false after MakeClient")
	}
	if after := fleetRev(t, d); after == before {
		t.Errorf("fleet_rev not bumped (still %q)", after)
	}

	var wrote []byte
	for _, c := range dialer.snapshot() {
		if c.op == "write" && c.path == "/root/.ssh/authorized_keys" {
			wrote = c.content
		}
	}
	if wrote == nil {
		t.Fatal("authorized_keys was not written")
	}
	caPub, err := ca.LoadPublicKey(dataDir + "/ca")
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	caKeyField := bytes.Fields(bytes.TrimSpace(caPub))[1]
	if bytes.Contains(wrote, caKeyField) {
		t.Errorf("pushed authorized_keys still contains the CA key:\n%s", wrote)
	}
	if bytes.Contains(wrote, []byte("cert-authority")) {
		t.Errorf("pushed authorized_keys still contains a cert-authority line:\n%s", wrote)
	}
	if !bytes.Contains(wrote, []byte("operator@laptop")) {
		t.Errorf("pushed authorized_keys dropped the non-CA line (outbound identity must survive):\n%s", wrote)
	}
}

func TestMakeClientAlreadyClientNoOp(t *testing.T) {
	dataDir, d := setupOpsEnv(t)
	ctx := context.Background()
	_, pubAuth, _, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	if err := d.InsertPeer(ctx, "laptop", 1, "fp", pubAuth, "alice", false, "tok"); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}

	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	if err := MakeClient(ctx, deps, "laptop", "mgr"); err != nil {
		t.Fatalf("MakeClient on already-client must be a clear no-op, got: %v", err)
	}
	if len(dialer.dialedHosts) != 0 {
		t.Errorf("already-client peer must not be dialed; dialed=%v", dialer.dialedHosts)
	}
	if len(events) != 1 || events[0].Type != EventInfo || !strings.Contains(events[0].Msg, "already a client") {
		t.Errorf("events = %+v, want one info no-op notice", events)
	}
}

func TestMakeClientDialFailureLeavesInbound(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha")
	ctx := context.Background()
	dialer := &fakeDialer{failDial: map[string]error{"alpha": errors.New("connection refused")}}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	err := MakeClient(ctx, deps, "alpha", "mgr")
	if err == nil {
		t.Fatal("expected dial error")
	}
	if got, want := err.Error(), "ssh dial alpha: connection refused"; got != want {
		t.Errorf("err = %q, want %q", got, want)
	}
	p, err := d.GetPeer(ctx, "alpha")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if !p.Inbound {
		t.Error("inbound must remain true after a failed make-client dial")
	}
	if got := eventTypes(events); len(got) != 2 || got[0] != EventPeerStart || got[1] != EventPeerFailed {
		t.Errorf("event types = %v, want [PeerStart PeerFailed]", got)
	}
}
