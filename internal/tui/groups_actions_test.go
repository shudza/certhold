package tui

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/ops"
	"github.com/shudza/certhold/internal/peerfiles"
	"github.com/shudza/certhold/internal/sshpush"
)

// recPusher records every host its dial served, so a test can assert exactly
// which peers were pushed. failHosts forces WriteFileAtomic to error for the
// named hosts, surfacing a push failure through the progress modal.
type recPusher struct {
	host      string
	rec       *recDial
	failHosts map[string]bool
}

func (p recPusher) WriteFileAtomic(context.Context, string, []byte, fs.FileMode) error {
	if p.failHosts[p.host] {
		return errors.New("write refused by test")
	}
	return nil
}

// ReadFile returns a stock authorized_keys carrying a cert-authority line for
// the seeded CA, so the allowed-by rewrite path (RewritePrincipals) has a line
// to splice instead of erroring on "no cert-authority line matches CA".
func (p recPusher) ReadFile(context.Context, string) ([]byte, error) {
	return []byte(`cert-authority,principals="manager,infra" ` + p.rec.caLine + "\n"), nil
}
func (p recPusher) SpliceConfigBlock(context.Context, string, string, string) error { return nil }
func (p recPusher) ClearPeer(context.Context, peerfiles.RemotePaths, string, []ssh.PublicKey) error {
	return nil
}
func (p recPusher) ReloadSSHD(context.Context) error   { return nil }
func (p recPusher) VerifyHealth(context.Context) error { return nil }
func (p recPusher) Close() error                       { return nil }

type recDial struct {
	mu        sync.Mutex
	hosts     []string
	failHosts map[string]bool
	caLine    string // trimmed CA authorized-key line, for ReadFile
}

func (r *recDial) dial(_ context.Context, host string, _ sshpush.Options) (sshpush.Pusher, error) {
	r.mu.Lock()
	r.hosts = append(r.hosts, host)
	r.mu.Unlock()
	return recPusher{host: host, rec: r, failHosts: r.failHosts}, nil
}

func (r *recDial) dialed() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]string(nil), r.hosts...)
	sort.Strings(out)
	return out
}

// recModel builds an action Model whose Dial records pushed hosts. Same seed as
// seedActionEnv (alpha in infra/db + allowed infra, beta in infra + allowed
// infra; group ops also present).
func recModel(t *testing.T, dataDir string, d *db.DB, rec *recDial) Model {
	t.Helper()
	caAK, err := ca.LoadPublicKey(filepath.Join(dataDir, "ca"))
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	rec.caLine = strings.TrimRight(string(caAK), "\n")
	reload := func(ctx context.Context) (fleetData, error) {
		return load(ctx, d, filepath.Join(dataDir, "state.db"))
	}
	data, err := reload(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	m := NewModel(context.Background(), data, reload)
	m = m.withAction(ActionDeps{
		Hostname: "alpha",
		BuildDeps: func(onEvent func(ops.Event), caUnlock, peerPass func() ([]byte, error), hostKeyConfirm func(host, fingerprint, keyType string) (bool, error)) ops.Deps {
			return ops.Deps{
				DB:             d,
				DataDir:        dataDir,
				CAUnlock:       caUnlock,
				PeerPass:       peerPass,
				Dial:           rec.dial,
				OnEvent:        onEvent,
				HostKeyConfirm: hostKeyConfirm,
			}
		},
	})
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = nm.(Model)
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("2")}) // groups view
	return nm.(Model)
}

func groupMembers(t *testing.T, d *db.DB, name string) []string {
	t.Helper()
	mem, err := d.GetGroupMembers(context.Background(), name)
	if err != nil {
		t.Fatalf("GetGroupMembers %s: %v", name, err)
	}
	sort.Strings(mem)
	return mem
}

func groupExists(t *testing.T, d *db.DB, name string) bool {
	t.Helper()
	ok, err := d.GroupExists(context.Background(), name)
	if err != nil {
		t.Fatalf("GroupExists %s: %v", name, err)
	}
	return ok
}

// typeRunes feeds a multi-char string into the focused text/passphrase modal.
func typeRunes(m Model, s string) Model {
	for _, r := range s {
		nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = nm.(Model)
	}
	return m
}

func selectGroup(t *testing.T, m Model, name string) Model {
	t.Helper()
	for i := 0; i < len(m.data.Groups)+2; i++ {
		if g, ok := m.selectedGroup(); ok && g.Name == name {
			return m
		}
		m = press(t, m, "j")
	}
	t.Fatalf("group %q not selectable", name)
	return m
}

// TestTextModalCharLimitPerKind: bubbles truncates in SetValue too, so the
// edit-address modal must carry the validator's 255-byte budget or a long
// prefilled address is silently corrupted on an untouched submit. Group-name
// modals keep the short limit.
func TestTextModalCharLimitPerKind(t *testing.T) {
	long := strings.Repeat("a", 60) + ".very-long-subdomain.example.com" // 92 chars
	tm := newTextModal("address alpha", "address: ", long, textEditAddress, "alpha")
	if tm.input.CharLimit != 255 {
		t.Errorf("edit-address CharLimit = %d, want 255", tm.input.CharLimit)
	}
	if got := tm.input.Value(); got != long {
		t.Errorf("edit-address prefill truncated: %q (len %d), want len %d", got, len(got), len(long))
	}

	gm := newTextModal("rename infra", "new name: ", "infra", textRenameGroup, "infra")
	if gm.input.CharLimit != 64 {
		t.Errorf("group-name CharLimit = %d, want 64", gm.input.CharLimit)
	}
}

// TestGroupCreate: n → type name → ops.GroupCreate; reload shows the new group.
func TestGroupCreate(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	rec := &recDial{}
	m := recModel(t, dataDir, d, rec)

	m = press(t, m, "n")
	if _, ok := topAny(m).(textModal); !ok {
		t.Fatalf("n did not open text modal; top=%T", topAny(m))
	}
	m = typeRunes(m, "edge")
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd, pass) // create needs no CA, but pass is harmless

	if !groupExists(t, d, "edge") {
		t.Fatal("db: group edge not created")
	}
	found := false
	for _, g := range m.data.Groups {
		if g.Name == "edge" {
			found = true
		}
	}
	if !found {
		t.Fatal("reloaded data does not show group edge")
	}
}

// TestGroupRename: R on infra → new name → ops.GroupRename re-signs members and
// rewrites allowing peers; reload shows the rename.
func TestGroupRename(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	rec := &recDial{}
	m := recModel(t, dataDir, d, rec)
	m = selectGroup(t, m, "infra")

	m = press(t, m, "R")
	tm, ok := topAny(m).(textModal)
	if !ok {
		t.Fatalf("R did not open text modal; top=%T", topAny(m))
	}
	if tm.input.Value() != "infra" {
		t.Fatalf("rename modal not seeded with current name: %q", tm.input.Value())
	}
	// Clear "infra" then type "core".
	for range "infra" {
		nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
		m = nm.(Model)
	}
	m = typeRunes(m, "core")
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd, pass)

	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("rename not done-ok: %+v", topAny(m))
	}
	if groupExists(t, d, "infra") || !groupExists(t, d, "core") {
		t.Fatal("db: rename infra→core did not take")
	}
	if g := peerGroupsSorted(t, d, "alpha"); strings.Join(g, ",") != "core,db" {
		t.Fatalf("alpha groups after rename = %v, want [core db]", g)
	}
}

func peerGroupsSorted(t *testing.T, d *db.DB, name string) []string {
	g := peerGroups(t, d, name)
	sort.Strings(g)
	return g
}

// TestGroupDeleteShowsImpactAndPushes: D confirm body lists members + allowed-by;
// proceeding re-signs members and rewrites allowing peers (per-peer push events),
// then deletes the group.
func TestGroupDeleteShowsImpact(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	rec := &recDial{}
	m := recModel(t, dataDir, d, rec)
	m = selectGroup(t, m, "infra")

	m = press(t, m, "D")
	cm, ok := topAny(m).(confirmModal)
	if !ok {
		t.Fatalf("D did not open confirm modal; top=%T", topAny(m))
	}
	body := strings.Join(cm.body, "\n")
	if !strings.Contains(body, "re-signed") || !strings.Contains(body, "rewrites") {
		t.Fatalf("delete confirm body omits impact: %q", body)
	}
	// infra members alpha+beta are also allowed-by infra → both pushed.
	if !strings.Contains(body, "alpha") || !strings.Contains(body, "beta") {
		t.Fatalf("delete confirm body omits affected peers: %q", body)
	}

	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = drain(t, nm.(Model), cmd, pass)

	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("delete not done-ok: %+v", topAny(m))
	}
	if groupExists(t, d, "infra") {
		t.Fatal("db: group infra not deleted")
	}
	// Both inbound member/allowed peers were pushed.
	if got := rec.dialed(); strings.Join(got, ",") != "alpha,beta" {
		t.Fatalf("delete pushed hosts = %v, want [alpha beta]", got)
	}
	pg := topAny(m).(progressModal)
	tr := strings.Join(pg.lines, "\n")
	if !strings.Contains(tr, "alpha") || !strings.Contains(tr, "beta") {
		t.Fatalf("progress transcript missing per-peer lines: %q", tr)
	}
}

// TestGroupDeletePushFailureSurfaces: a push failure on one peer leaves the
// group undeleted (straggler) and surfaces the failure in the progress modal.
func TestGroupDeletePushFailureSurfaces(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	rec := &recDial{failHosts: map[string]bool{"beta": true}}
	m := recModel(t, dataDir, d, rec)
	m = selectGroup(t, m, "infra")

	m = press(t, m, "D")
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = drain(t, nm.(Model), cmd, pass)

	pg, ok := topAny(m).(progressModal)
	if !ok || !pg.done {
		t.Fatalf("expected done progress modal, got %+v", topAny(m))
	}
	if pg.err == nil {
		t.Fatal("expected straggler error surfaced in progress modal")
	}
	tr := strings.Join(pg.lines, "\n")
	if !strings.Contains(tr, "beta") || !strings.Contains(tr, "✗") {
		t.Fatalf("progress transcript missing the failed peer: %q", tr)
	}
	if !groupExists(t, d, "infra") {
		t.Fatal("db: group deleted despite a straggler push failure")
	}
}

// TestMembershipDiffOnlyChangedPeersPushed is the core AC: a pre-checked picker,
// applied with one add and no removal, re-signs/pushes ONLY the changed peer.
func TestMembershipDiffOnlyChangedPeersPushed(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	rec := &recDial{}
	m := recModel(t, dataDir, d, rec)
	// db currently has only alpha as a member (it has infra+db; beta has infra).
	m = selectGroup(t, m, "db")

	m = press(t, m, "m")
	pick, ok := topAny(m).(pickModal)
	if !ok || pick.kind != pickGroupMembers {
		t.Fatalf("m did not open members pick; top=%T", topAny(m))
	}
	if !pick.checked["alpha"] || pick.checked["beta"] {
		t.Fatalf("members pre-check wrong: %+v", pick.checked)
	}
	// Toggle beta ON (add). alpha stays checked (unchanged). Move cursor to beta.
	// options sorted: [alpha beta]; cursor starts at alpha, move down to beta.
	m = press(t, m, "j")
	m = press(t, m, " ") // check beta
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd, pass)

	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("membership apply not done-ok: %+v", topAny(m))
	}
	// Only beta changed → only beta dialed. alpha (unchanged) must NOT be pushed.
	if got := rec.dialed(); strings.Join(got, ",") != "beta" {
		t.Fatalf("membership pushed hosts = %v, want [beta] (only changed peer)", got)
	}
	if mem := groupMembers(t, d, "db"); strings.Join(mem, ",") != "alpha,beta" {
		t.Fatalf("db group members = %v, want [alpha beta]", mem)
	}
}

// TestMembershipRemoveOnlyChangedPeer removes one member and asserts only it is
// pushed and its db groups lose the group.
func TestMembershipRemoveOnlyChangedPeer(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	rec := &recDial{}
	m := recModel(t, dataDir, d, rec)
	m = selectGroup(t, m, "infra") // members: alpha, beta

	m = press(t, m, "m")
	// Uncheck beta (remove); leave alpha. cursor at alpha → down to beta → toggle.
	m = press(t, m, "j")
	m = press(t, m, " ")
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd, pass)

	if got := rec.dialed(); strings.Join(got, ",") != "beta" {
		t.Fatalf("remove pushed hosts = %v, want [beta]", got)
	}
	if g := peerGroupsSorted(t, d, "beta"); strings.Join(g, ",") != "" {
		t.Fatalf("beta groups after removal = %v, want []", g)
	}
	if g := peerGroupsSorted(t, d, "alpha"); strings.Join(g, ",") != "db,infra" {
		t.Fatalf("alpha groups changed unexpectedly = %v", g)
	}
}

// TestMembershipNoOpOpensNoAction: applying with no change touches nothing.
func TestMembershipNoOpOpensNoAction(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	rec := &recDial{}
	m := recModel(t, dataDir, d, rec)
	m = selectGroup(t, m, "infra")

	m = press(t, m, "m")
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter}) // apply unchanged
	m = drain(t, nm.(Model), cmd)

	if _, ok := topAny(m).(progressModal); ok {
		t.Fatal("no-op membership opened a progress modal")
	}
	if got := rec.dialed(); len(got) != 0 {
		t.Fatalf("no-op membership pushed hosts = %v, want none", got)
	}
}

// TestMembershipSkipsRevokedMember reproduces the reviewer's repro: a group whose
// members include a revoked peer (ghost, still carrying a peer_groups row) plus a
// live peer (alpha). Editing membership to add beta must (a) never call
// ops.UpdatePeer on the revoked ghost — so ghost is never dialed and the action
// does not fail with "membership update incomplete", (b) succeed, and (c) apply
// the live toggle (beta gains infra) without disturbing alpha or ghost.
func TestMembershipSkipsRevokedMember(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	ctx := context.Background()
	// Reshape to the repro: alpha[infra,db] live (already seeded), beta[] live,
	// ghost[infra] revoked. beta starts with no groups so adding it is the live
	// toggle; ghost stays in infra but revoked (peer_groups row intact).
	if err := d.SetPeerGroups(ctx, "beta", nil); err != nil {
		t.Fatalf("SetPeerGroups beta: %v", err)
	}
	_, pubAuth, sshPub, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey ghost: %v", err)
	}
	if err := d.InsertPeer(ctx, "ghost", 200, ssh.FingerprintSHA256(sshPub), pubAuth, "root", true, ""); err != nil {
		t.Fatalf("InsertPeer ghost: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "ghost", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerGroups ghost: %v", err)
	}
	if err := d.SetPeerRevoked(ctx, "ghost"); err != nil {
		t.Fatalf("SetPeerRevoked ghost: %v", err)
	}

	rec := &recDial{}
	m := recModel(t, dataDir, d, rec)
	m = selectGroup(t, m, "infra")

	m = press(t, m, "m")
	pick, ok := topAny(m).(pickModal)
	if !ok || pick.kind != pickGroupMembers {
		t.Fatalf("m did not open members pick; top=%T", topAny(m))
	}
	// ghost is excluded from options entirely; alpha is the lone visible member.
	for _, o := range pick.options {
		if o == "ghost" {
			t.Fatalf("revoked ghost should not be a picker option: %v", pick.options)
		}
	}
	if !pick.checked["alpha"] || pick.checked["beta"] {
		t.Fatalf("members pre-check wrong: %+v", pick.checked)
	}
	// Select [alpha,beta]: options sorted [alpha beta], cursor at alpha → down → toggle beta on.
	m = press(t, m, "j")
	m = press(t, m, " ")
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd, pass)

	// (b) action succeeds — no "incomplete" failure from a phantom ghost delta.
	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("membership apply not done-ok: %+v", topAny(m))
	}
	// (a) ghost is never re-signed/pushed; only the changed live peer beta is dialed.
	if got := rec.dialed(); strings.Join(got, ",") != "beta" {
		t.Fatalf("membership pushed hosts = %v, want [beta] (ghost must not be touched)", got)
	}
	// (c) beta gains infra; alpha unchanged; ghost still in infra (untouched).
	if g := peerGroupsSorted(t, d, "beta"); strings.Join(g, ",") != "infra" {
		t.Fatalf("beta groups = %v, want [infra]", g)
	}
	if g := peerGroupsSorted(t, d, "alpha"); strings.Join(g, ",") != "db,infra" {
		t.Fatalf("alpha groups changed unexpectedly = %v", g)
	}
	if g := peerGroupsSorted(t, d, "ghost"); strings.Join(g, ",") != "infra" {
		t.Fatalf("revoked ghost groups changed = %v, want [infra] (untouched)", g)
	}
}

// TestAllowedGroupsEdit: i on a peer → toggle allowed group → SetPeerAllowedGroups
// updates the db and splices/pushes the inbound peer.
func TestAllowedGroupsEdit(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	rec := &recDial{}
	m := recModel(t, dataDir, d, rec)
	// switch to peers view, select alpha.
	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("1")})
	m = nm.(Model)

	m = press(t, m, "i")
	pick, ok := topAny(m).(pickModal)
	if !ok || pick.kind != pickPeerAllowed {
		t.Fatalf("i did not open allowed pick; top=%T", topAny(m))
	}
	if !pick.checked["infra"] {
		t.Fatalf("allowed pre-check wrong: %+v", pick.checked)
	}
	// Add "db" to allowed. options sorted [db infra ops]; cursor at db → toggle.
	if pick.options[0] != "db" {
		t.Fatalf("expected options[0]=db, got %q", pick.options[0])
	}
	m = press(t, m, " ") // check db (no CA passphrase needed for allowed edit)
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd)

	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("allowed edit not done-ok: %+v", topAny(m))
	}
	allowed, err := d.GetPeerAllowedGroups(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	sort.Strings(allowed)
	if strings.Join(allowed, ",") != "db,infra" {
		t.Fatalf("db allowed groups for alpha = %v, want [db infra]", allowed)
	}
	if got := rec.dialed(); strings.Join(got, ",") != "alpha" {
		t.Fatalf("allowed edit pushed hosts = %v, want [alpha]", got)
	}
}

// TestGroupKeysGatedToView checks the groups keys only act in the groups view
// and the peer-side allowed key only in the peers view.
func TestGroupKeysGatedToView(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	rec := &recDial{}
	m := recModel(t, dataDir, d, rec) // groups view

	// In peers view, group keys are inert.
	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("1")})
	pm := nm.(Model)
	for _, k := range []string{"n", "R", "D", "m"} {
		if mm := press(t, pm, k); func() bool { _, ok := mm.topModal(); return ok }() {
			t.Fatalf("peers view: group key %q opened a modal", k)
		}
	}
	// In groups view, the peer-side allowed key is inert.
	if mm := press(t, m, "i"); func() bool { _, ok := mm.topModal(); return ok }() {
		t.Fatal("groups view: i opened a modal")
	}
}

// TestReadOnlyBlocksGroupMutations checks --read-only opens no modal on any of
// the new keys.
func TestReadOnlyBlocksGroupMutations(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	reload := func(ctx context.Context) (fleetData, error) {
		return load(ctx, d, filepath.Join(dataDir, "state.db"))
	}
	data, _ := reload(context.Background())
	m := NewModel(context.Background(), data, reload)
	m.readOnly = true
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = nm.(Model)
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("2")}) // groups
	m = nm.(Model)

	for _, k := range []string{"n", "R", "D", "m", "i"} {
		if mm := press(t, m, k); func() bool { _, ok := mm.topModal(); return ok }() {
			t.Fatalf("read-only: key %q opened a modal", k)
		}
	}
}
