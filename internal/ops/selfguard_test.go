package ops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/peerfiles"
)

// seedSelfRow adds the manager's own peer row the way init mints it: an inbound
// root peer whose cert principals are its name PLUS the manager principal (which
// is never a group), allowing inbound from that principal. groups is the row's
// DB membership — empty for a fresh init, non-empty to model a legacy self
// membership added before the row was guarded.
func seedSelfRow(t *testing.T, dataDir string, d *db.DB, name string, groups []string) {
	t.Helper()
	ctx := context.Background()
	caObj, err := ca.Load(filepath.Join(dataDir, "ca"))
	if err != nil {
		t.Fatalf("ca.Load: %v", err)
	}
	_, pubAuth, sshPub, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	principals := append([]string{name, peerfiles.ManagerPrincipal}, groups...)
	certBytes, serial, err := caObj.SignCert(ca.SignOptions{Pubkey: sshPub, KeyID: name, Principals: principals})
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	if err := d.EnsureGroup(ctx, peerfiles.ManagerPrincipal); err != nil {
		t.Fatalf("EnsureGroup manager: %v", err)
	}
	if err := d.InsertPeer(ctx, name, serial, ssh.FingerprintSHA256(sshPub), pubAuth, "root", true, ""); err != nil {
		t.Fatalf("InsertPeer %s: %v", name, err)
	}
	if err := d.SetPeerCert(ctx, name, certBytes, serial); err != nil {
		t.Fatalf("SetPeerCert %s: %v", name, err)
	}
	if len(groups) > 0 {
		if err := d.SetPeerGroups(ctx, name, groups); err != nil {
			t.Fatalf("SetPeerGroups %s: %v", name, err)
		}
	}
	if err := d.SetPeerAllowedGroups(ctx, name, []string{peerfiles.ManagerPrincipal}); err != nil {
		t.Fatalf("SetPeerAllowedGroups %s: %v", name, err)
	}
}

func storedCert(t *testing.T, d *db.DB, name string) []byte {
	t.Helper()
	p, err := d.GetPeer(context.Background(), name)
	if err != nil {
		t.Fatalf("GetPeer %s: %v", name, err)
	}
	if len(p.Cert) == 0 {
		t.Fatalf("peer %s has no stored cert", name)
	}
	return p.Cert
}

// storedPrincipals decodes the peer's stored cert and returns its principals.
func storedPrincipals(t *testing.T, d *db.DB, name string) []string {
	t.Helper()
	pk, _, _, _, err := ssh.ParseAuthorizedKey(storedCert(t, d, name))
	if err != nil {
		t.Fatalf("parse stored cert %s: %v", name, err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		t.Fatalf("stored %s cert is %T, want *ssh.Certificate", name, pk)
	}
	return cert.ValidPrincipals
}

// assertManagerPrincipal is the invariant every self-row edit path must keep:
// the manager's stored cert still names itself and the manager principal.
func assertManagerPrincipal(t *testing.T, d *db.DB, name string) {
	t.Helper()
	got := storedPrincipals(t, d, name)
	var hasSelf, hasManager bool
	for _, p := range got {
		switch p {
		case name:
			hasSelf = true
		case peerfiles.ManagerPrincipal:
			hasManager = true
		}
	}
	if !hasSelf || !hasManager {
		t.Fatalf("self cert principals = %v, want to contain %q and %q", got, name, peerfiles.ManagerPrincipal)
	}
}

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

// TestSelfNamePrefersPersistedName pins the T168 regression: the self name
// persisted at init wins over the OS hostname, so pushes and guards keep
// working when `init --hostname` named the manager differently (or the host
// was renamed after init).
func TestSelfNamePrefersPersistedName(t *testing.T) {
	selfGuardSetHostname(t, "os-name")
	_, d := setupOpsEnv(t, "mgr", "alpha")
	ctx := context.Background()
	if err := d.SetMeta(ctx, db.MetaSelfName, "mgr"); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}

	if got, err := SelfName(ctx, d); err != nil || got != "mgr" {
		t.Fatalf("SelfName = (%q, %v), want (\"mgr\", nil)", got, err)
	}

	var events []Event
	deps := noDialDeps(t, d, &events)
	err := RemovePeer(ctx, deps, "mgr")
	selfGuardCheckErr(t, err, "RemovePeer (persisted self name)")
	selfGuardCheckRowIntact(t, d)
}

func TestSelfNameFallsBackToOSHostname(t *testing.T) {
	selfGuardSetHostname(t, "legacy-host")
	_, d := setupOpsEnv(t, "mgr")
	if got, err := SelfName(context.Background(), d); err != nil || got != "legacy-host" {
		t.Fatalf("SelfName = (%q, %v), want (\"legacy-host\", nil)", got, err)
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

// TestSelfCertKeepsManagerPrincipalAcrossEditPaths pins the invariant the whole
// self-row guard exists for: after EVERY group-shaped edit path that still runs
// against the manager's own row, its stored cert still carries the manager
// principal. Peers authorize inbound manager SSH with it, so a re-sign that
// drops it locks the manager out of pushing to its own fleet. The row starts
// with a legacy membership, which only a pre-guard `update` could have created.
func TestSelfCertKeepsManagerPrincipalAcrossEditPaths(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha")
	ctx := context.Background()
	seedSelfRow(t, dataDir, d, "mgr", []string{"infra"})
	dialer := &fakeDialer{
		readData: map[string][]byte{"/root/.ssh/authorized_keys": opsCALine(t, dataDir, "manager", "infra")},
	}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	// 1. update: refused outright, cert untouched.
	if err := UpdatePeer(ctx, deps, "mgr", []string{"infra"}, "", "mgr"); err == nil {
		t.Fatal("UpdatePeer against the self row must be refused")
	}
	assertManagerPrincipal(t, d, "mgr")

	// 2. allowed-inbound edit: legitimate (it re-signs nothing).
	if err := SetPeerAllowedGroups(ctx, deps, "mgr", []string{peerfiles.ManagerPrincipal, "infra"}, "", "mgr"); err != nil {
		t.Fatalf("SetPeerAllowedGroups: %v", err)
	}
	assertManagerPrincipal(t, d, "mgr")

	// 3. group rename cascade: the self row IS a member, so its cert is
	// re-signed — with the manager principal preserved.
	if err := GroupRename(ctx, deps, "infra", "core", "mgr"); err != nil {
		t.Fatalf("GroupRename: %v", err)
	}
	assertManagerPrincipal(t, d, "mgr")
	if got := strings.Join(storedPrincipals(t, d, "mgr"), ","); got != "mgr,manager,core" {
		t.Errorf("self principals after rename = %q, want \"mgr,manager,core\"", got)
	}

	// 4. group delete cascade: same, minus the deleted group.
	if err := GroupDelete(ctx, deps, "core", "mgr"); err != nil {
		t.Fatalf("GroupDelete: %v", err)
	}
	assertManagerPrincipal(t, d, "mgr")
	if got := strings.Join(storedPrincipals(t, d, "mgr"), ","); got != "mgr,manager" {
		t.Errorf("self principals after delete = %q, want \"mgr,manager\"", got)
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
