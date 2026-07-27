package ops

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
)

// opsCALine builds a cert-authority authorized_keys line carrying the CA
// pubkey at dataDir/ca, matching what peerfiles.BuildUser installs.
func opsCALine(t *testing.T, dataDir string, principals ...string) []byte {
	t.Helper()
	caPub, err := ca.LoadPublicKey(filepath.Join(dataDir, "ca"))
	if err != nil {
		t.Fatalf("ca.LoadPublicKey: %v", err)
	}
	caTrim := strings.TrimRight(string(caPub), "\n")
	return []byte(`cert-authority,principals="` + strings.Join(principals, ",") + `" ` + caTrim + "\n")
}

func TestGroupDeleteResignPushLoopWithInjectedFailure(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha", "beta")
	ctx := context.Background()
	dialer := &fakeDialer{
		failDial: map[string]error{"beta": errors.New("connection refused")},
		readData: map[string][]byte{"/root/.ssh/authorized_keys": opsCALine(t, dataDir, "manager", "infra")},
	}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	err := GroupDelete(ctx, deps, "infra", "")
	if err == nil {
		t.Fatal("expected straggler error")
	}
	if got, want := err.Error(), "group delete incomplete: 1 straggler(s)"; got != want {
		t.Errorf("err = %q, want %q", got, want)
	}

	want := []Event{
		{Type: EventPeerStart, Peer: "alpha"},
		{Type: EventPeerDone, Peer: "alpha"},
		{Type: EventPeerStart, Peer: "beta"},
	}
	if len(events) != 5 {
		t.Fatalf("events = %+v, want 5 (start/done alpha, start/failed beta, warn)", events)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Errorf("event[%d] = %+v, want %+v", i, events[i], want[i])
		}
	}
	failed := events[3]
	if failed.Type != EventPeerFailed || failed.Peer != "beta" || failed.Err == nil || failed.Err.Error() != "ssh dial beta: connection refused" {
		t.Errorf("event[3] = %+v, want PeerFailed beta with dial error", failed)
	}
	warn := events[4]
	if warn.Type != EventWarn || warn.Msg != "peers with unfinished pushes (DB not deleted): beta" {
		t.Errorf("event[4] = %+v, want straggler warn line", warn)
	}

	if ok, _ := d.GroupExists(ctx, "infra"); !ok {
		t.Error("group 'infra' must still exist after straggler")
	}
	for _, name := range []string{"alpha", "beta"} {
		groups, err := d.GetPeerGroups(ctx, name)
		if err != nil {
			t.Fatalf("GetPeerGroups %s: %v", name, err)
		}
		if len(groups) != 0 {
			t.Errorf("%s groups = %v, want [] (DB updated for attempted peers)", name, groups)
		}
	}

	var alphaCert []byte
	var alphaOps []string
	for _, c := range dialer.snapshot() {
		if c.host == "beta" {
			t.Errorf("unreachable beta must not receive pushes: %+v", c)
			continue
		}
		alphaOps = append(alphaOps, c.op)
		if c.op == "write" && strings.HasSuffix(c.path, "-cert.pub") {
			alphaCert = c.content
		}
	}
	wantOps := []string{"write", "read", "write", "verify"}
	if strings.Join(alphaOps, ",") != strings.Join(wantOps, ",") {
		t.Errorf("alpha push ops = %v, want %v", alphaOps, wantOps)
	}
	if alphaCert == nil {
		t.Fatal("no re-signed cert pushed to alpha")
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(alphaCert)
	if err != nil {
		t.Fatalf("parse pushed cert: %v", err)
	}
	cert := pk.(*ssh.Certificate)
	if strings.Join(cert.ValidPrincipals, ",") != "alpha" {
		t.Errorf("re-signed principals = %v, want [alpha] (infra removed)", cert.ValidPrincipals)
	}
}

func TestGroupDeleteSuccessSummaryEvent(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha")
	ctx := context.Background()
	dialer := &fakeDialer{
		readData: map[string][]byte{"/root/.ssh/authorized_keys": opsCALine(t, dataDir, "manager", "infra")},
	}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	if err := GroupDelete(ctx, deps, "infra", ""); err != nil {
		t.Fatalf("GroupDelete: %v", err)
	}
	if ok, _ := d.GroupExists(ctx, "infra"); ok {
		t.Error("group 'infra' should be deleted")
	}
	last := events[len(events)-1]
	if last.Type != EventInfo || last.Msg != `group "infra" deleted; affected peers: alpha` {
		t.Errorf("summary event = %+v", last)
	}
	for _, e := range events[:len(events)-1] {
		if e.Type == EventPeerDone && e.Msg != "" {
			t.Errorf("group per-peer EventPeerDone must carry no Msg: %+v", e)
		}
	}
}

// TestGroupDeleteKeepsManagerPrincipalOnSelfMember: a legacy self membership
// (only a pre-guard `update` could create one) still cascades — the row's DB
// groups lose the deleted group and its cert is re-signed — but the re-sign
// keeps the manager principal, which lives on the cert and in no group.
func TestGroupDeleteKeepsManagerPrincipalOnSelfMember(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha")
	ctx := context.Background()
	seedSelfRow(t, dataDir, d, "mgr", []string{"infra"})
	dialer := &fakeDialer{
		readData: map[string][]byte{"/root/.ssh/authorized_keys": opsCALine(t, dataDir, "manager", "infra")},
	}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	if err := GroupDelete(ctx, deps, "infra", "mgr"); err != nil {
		t.Fatalf("GroupDelete: %v", err)
	}
	if got := strings.Join(storedPrincipals(t, d, "mgr"), ","); got != "mgr,manager" {
		t.Errorf("self principals = %q, want \"mgr,manager\"", got)
	}
	groups, err := d.GetPeerGroups(ctx, "mgr")
	if err != nil {
		t.Fatalf("GetPeerGroups: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("self groups = %v, want [] (deleted group dropped)", groups)
	}
	if got := strings.Join(storedPrincipals(t, d, "alpha"), ","); got != "alpha" {
		t.Errorf("alpha principals = %q, want \"alpha\" (no manager principal granted)", got)
	}
}

// TestGroupRenameKeepsManagerPrincipalOnSelfMember: same for the rename
// cascade, which re-signs members against the renamed group.
func TestGroupRenameKeepsManagerPrincipalOnSelfMember(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha")
	ctx := context.Background()
	seedSelfRow(t, dataDir, d, "mgr", []string{"infra"})
	dialer := &fakeDialer{
		readData: map[string][]byte{"/root/.ssh/authorized_keys": opsCALine(t, dataDir, "manager", "infra")},
	}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	if err := GroupRename(ctx, deps, "infra", "core", "mgr"); err != nil {
		t.Fatalf("GroupRename: %v", err)
	}
	if got := strings.Join(storedPrincipals(t, d, "mgr"), ","); got != "mgr,manager,core" {
		t.Errorf("self principals = %q, want \"mgr,manager,core\"", got)
	}
	if got := strings.Join(storedPrincipals(t, d, "alpha"), ","); got != "alpha,core" {
		t.Errorf("alpha principals = %q, want \"alpha,core\"", got)
	}
}

func TestSetPeerAllowedGroupsClientPeerNoticeNoDial(t *testing.T) {
	dataDir, d := setupOpsEnv(t)
	ctx := context.Background()
	_, pubAuth, sshPub, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	if err := d.InsertPeer(ctx, "laptop", 1, ssh.FingerprintSHA256(sshPub), pubAuth, "alice", false, "tok"); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}

	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	if err := SetPeerAllowedGroups(ctx, deps, "laptop", nil, "", ""); err != nil {
		t.Fatalf("SetPeerAllowedGroups: %v", err)
	}
	if calls := dialer.snapshot(); len(calls) != 0 {
		t.Errorf("client peer must not be dialed; calls=%+v", calls)
	}
	if len(events) != 1 || events[0].Type != EventInfo || events[0].Msg != ClientPeerNoticeMsg("laptop") {
		t.Errorf("events = %+v, want single client-peer notice", events)
	}
}
