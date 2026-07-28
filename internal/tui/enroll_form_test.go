package tui

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/ops"
)

// openEnroll opens the form and moves focus to the named field index.
func openEnroll(t *testing.T, m Model) (Model, enrollFormModal) {
	t.Helper()
	m = press(t, m, "e")
	ef, ok := topAny(m).(enrollFormModal)
	if !ok {
		t.Fatalf("e did not open enroll form; top=%T", topAny(m))
	}
	return m, ef
}

// gotoField tabs forward until the form's focus reaches field.
func gotoField(m Model, field int) Model {
	for i := 0; i < efCount; i++ {
		if ef, ok := topAny(m).(enrollFormModal); ok && ef.field == field {
			return m
		}
		nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
		m = nm.(Model)
	}
	return m
}

// TestEnrollValidationEmptyName: an empty name leaves submit inert (validateName
// non-empty) and the form open; no peer is minted.
func TestEnrollValidationEmptyName(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	m := actionModel(t, dataDir, d)
	m, _ = openEnroll(t, m)

	m = gotoField(m, efSubmit)
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = nm.(Model)
	if cmd != nil {
		t.Fatal("empty-name submit launched an action")
	}
	ef, ok := topAny(m).(enrollFormModal)
	if !ok {
		t.Fatalf("empty-name submit closed the form; top=%T", topAny(m))
	}
	if ef.validateName() == "" {
		t.Fatal("empty name unexpectedly validated")
	}
	if !strings.Contains(strings.Join(ef.view(80, 24), "\n"), "required") {
		t.Fatalf("empty-name form omits the required note:\n%s", strings.Join(ef.view(80, 24), "\n"))
	}
}

// TestEnrollValidationDuplicateName: a name that already exists (alpha) is
// rejected by validateName and never mints.
func TestEnrollValidationDuplicateName(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	m := actionModel(t, dataDir, d)
	m, _ = openEnroll(t, m)

	m = typeRunes(m, "alpha") // existing peer
	ef := topAny(m).(enrollFormModal)
	if got := ef.validateName(); !strings.Contains(got, "already exists") {
		t.Fatalf("duplicate name validateName = %q, want 'already exists'", got)
	}
	m = gotoField(m, efSubmit)
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Fatal("duplicate-name submit launched an action")
	}
	if _, ok := nm.(Model).topModal(); !ok {
		t.Fatal("duplicate-name submit closed the form")
	}
}

// TestEnrollSuccessMintsAndShowsOneLiner: a full form with a fresh name mints a
// peer + token in the db and renders the result one-liner (uncut) at 120/80/60.
func TestEnrollSuccessMintsAndShowsOneLiner(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	m := actionModel(t, dataDir, d)
	m, _ = openEnroll(t, m)

	m = typeRunes(m, "edge1")
	// Toggle one group on (infra) and one allowed (infra) so the picker fields
	// are exercised; options sorted [db infra ops], cursor at db → j to infra.
	m = gotoField(m, efGroups)
	m = press(t, m, "j") // db -> infra
	m = press(t, m, " ") // check infra
	m = gotoField(m, efAllowed)
	m = press(t, m, "j")
	m = press(t, m, " ")
	m = gotoField(m, efSubmit)
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd, pass)

	res, ok := topAny(m).(enrollResultModal)
	if !ok {
		t.Fatalf("enroll did not land on the result screen; top=%T (%+v)", topAny(m), topAny(m))
	}
	if res.peer != "edge1" {
		t.Fatalf("result peer = %q, want edge1", res.peer)
	}
	if !strings.HasPrefix(res.oneLiner, "curl -kfsSL ") || !strings.Contains(res.oneLiner, "/enroll/") {
		t.Fatalf("one-liner malformed: %q", res.oneLiner)
	}

	// db side-effects: peer row + token present.
	if _, err := d.GetPeer(context.Background(), "edge1"); err != nil {
		t.Fatalf("edge1 not inserted: %v", err)
	}
	if g := peerGroupsSorted(t, d, "edge1"); strings.Join(g, ",") != "infra" {
		t.Fatalf("edge1 groups = %v, want [infra]", g)
	}

	// The one-liner must appear UNCUT (no ellipsis, every char present) at each
	// width: concatenating the wrapped rows reproduces the exact one-liner.
	for _, w := range []int{120, 80, 60} {
		nm, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: 30})
		mm := nm.(Model)
		v := mm.View()
		// The one-liner is wrapped, never truncated: each wrapped segment must
		// appear verbatim in the rendered view, and concatenating the modal's
		// own wrapped rows reproduces the exact one-liner (no … anywhere in it).
		rows := wrapPlain(res.oneLiner, w-4)
		if strings.Join(rows, "") != res.oneLiner {
			t.Fatalf("width %d: wrapped one-liner != original\n got=%q\nwant=%q", w, strings.Join(rows, ""), res.oneLiner)
		}
		for _, seg := range rows {
			if !strings.Contains(v, seg) {
				t.Fatalf("width %d: one-liner segment missing from view (truncated?): %q\n%s", w, seg, v)
			}
		}
		// Every rendered line stays within width (fixed-frame invariant).
		for _, l := range strings.Split(v, "\n") {
			if lw := lipgloss.Width(l); lw > w {
				t.Fatalf("width %d: line overflows (%d): %q", w, lw, l)
			}
		}
	}

	// esc dismisses the result screen.
	m = press(t, m, "esc")
	if _, ok := m.topModal(); ok {
		t.Fatalf("esc did not dismiss result screen; top=%T", topAny(m))
	}
}

// TestEnrollEscCancels: esc at any field closes the whole form, minting nothing.
func TestEnrollEscCancels(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	m := actionModel(t, dataDir, d)
	m, _ = openEnroll(t, m)
	m = typeRunes(m, "edge2")
	m = gotoField(m, efAllowed)
	m = press(t, m, "esc")
	if _, ok := m.topModal(); ok {
		t.Fatalf("esc did not cancel form; top=%T", topAny(m))
	}
	if _, err := d.GetPeer(context.Background(), "edge2"); err == nil {
		t.Fatal("esc-cancel still minted edge2")
	}
}

// TestEnrollReadOnlyGated: --read-only opens no enroll form.
func TestEnrollReadOnlyGated(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	m := readOnlyModel(t, dataDir, d)
	if mm := press(t, m, "e"); func() bool { _, ok := mm.topModal(); return ok }() {
		t.Fatal("read-only: e opened the enroll form")
	}
}

// seedReenrollTUIEnv builds a PLAINTEXT-CA env (no passphrase modal, safe for
// -race repetition) with: alpha (inbound, hidden manager membership+allowed,
// user alice, address 10.0.0.7), cli1 (client-style), revd (revoked), and the
// manager's own row mgr (= selfRowName).
func seedReenrollTUIEnv(t *testing.T) (string, *db.DB) {
	t.Helper()
	dataDir := t.TempDir()
	if _, err := ca.Generate(filepath.Join(dataDir, "ca")); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	d, err := db.Open(filepath.Join(dataDir, "state.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	ctx := context.Background()
	if _, err := ops.EnsureInstanceKey(ctx, d); err != nil {
		t.Fatalf("EnsureInstanceKey: %v", err)
	}
	for _, g := range []string{"infra", "db", "manager"} {
		if err := d.EnsureGroup(ctx, g); err != nil {
			t.Fatalf("EnsureGroup %s: %v", g, err)
		}
	}
	seed := func(name, user string, inbound bool) {
		_, pubAuth, sshPub, err := ca.GeneratePeerKey()
		if err != nil {
			t.Fatalf("GeneratePeerKey %s: %v", name, err)
		}
		if err := d.InsertPeer(ctx, name, 100, ssh.FingerprintSHA256(sshPub), pubAuth, user, inbound, ""); err != nil {
			t.Fatalf("InsertPeer %s: %v", name, err)
		}
	}
	seed("alpha", "alice", true)
	if err := d.SetPeerGroups(ctx, "alpha", []string{"infra", "manager"}); err != nil {
		t.Fatalf("SetPeerGroups alpha: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "alpha", []string{"infra", "manager"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups alpha: %v", err)
	}
	if err := d.SetPeerAddress(ctx, "alpha", "10.0.0.7"); err != nil {
		t.Fatalf("SetPeerAddress alpha: %v", err)
	}
	seed("cli1", "alice", false)
	if err := d.SetPeerGroups(ctx, "cli1", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerGroups cli1: %v", err)
	}
	seed("revd", "alice", true)
	if err := d.SetPeerRevoked(ctx, "revd"); err != nil {
		t.Fatalf("SetPeerRevoked revd: %v", err)
	}
	seed(selfRowName, "alice", true)
	return dataDir, d
}

// openPeerDetail moves the peers-table selection to name and opens its detail
// pane with enter.
func openPeerDetail(t *testing.T, m Model, name string) Model {
	t.Helper()
	for i := 0; i < len(m.filteredPeers()); i++ {
		if p, ok := m.selectedPeer(); ok && p.Name == name {
			break
		}
		m = press(t, m, "j")
	}
	if p, ok := m.selectedPeer(); !ok || p.Name != name {
		t.Fatalf("could not select peer %q", name)
	}
	m = press(t, m, "enter")
	if !m.detail || m.detailName != name {
		t.Fatalf("detail pane did not open for %q (detail=%v name=%q)", name, m.detail, m.detailName)
	}
	return m
}

// TestReenrollKeyPrefillsFromPeer: E on the detail page opens the re-enroll
// form pre-filled from the peer's config, with the hidden manager principal
// absent from the pickers (T162) and the name locked.
func TestReenrollKeyPrefillsFromPeer(t *testing.T) {
	dataDir, d := seedReenrollTUIEnv(t)
	m := actionModel(t, dataDir, d)
	m = openPeerDetail(t, m, "alpha")
	m = press(t, m, "E")

	ef, ok := topAny(m).(enrollFormModal)
	if !ok {
		t.Fatalf("E did not open the re-enroll form; top=%T", topAny(m))
	}
	if !ef.reenroll || ef.fixedName != "alpha" {
		t.Fatalf("form = reenroll=%v fixedName=%q, want re-enroll of alpha", ef.reenroll, ef.fixedName)
	}
	if ef.title() != "re-enroll alpha" {
		t.Errorf("title = %q, want re-enroll alpha", ef.title())
	}
	for _, o := range ef.groupOpts {
		if o == "manager" {
			t.Error("manager offered in the groups picker (must stay hidden)")
		}
	}
	for _, o := range ef.allowOpts {
		if o == "manager" {
			t.Error("manager offered in the allowed picker (must stay hidden)")
		}
	}
	if !ef.groupSet["infra"] || ef.groupSet["db"] {
		t.Errorf("groupSet = %v, want infra pre-checked only", ef.groupSet)
	}
	if !ef.allowSet["infra"] || ef.allowSet["db"] {
		t.Errorf("allowSet = %v, want infra pre-checked only", ef.allowSet)
	}
	if got := ef.user.Value(); got != "alice" {
		t.Errorf("user = %q, want alice", got)
	}
	if got := ef.address.Value(); got != "10.0.0.7" {
		t.Errorf("address = %q, want 10.0.0.7", got)
	}
	if ef.client {
		t.Error("client = true for an inbound peer, want false")
	}
	v := strings.Join(ef.view(80, 24), "\n")
	if !strings.Contains(v, "alpha") || !strings.Contains(v, "existing peer — fixed") {
		t.Errorf("view missing locked-name rendering:\n%s", v)
	}
	if !strings.Contains(v, "nothing changes on the peer until") {
		t.Errorf("view missing the staged-mint note:\n%s", v)
	}
}

// TestReenrollClientPeerPrefill: a client-style peer opens with the client
// toggle set.
func TestReenrollClientPeerPrefill(t *testing.T) {
	dataDir, d := seedReenrollTUIEnv(t)
	m := actionModel(t, dataDir, d)
	m = openPeerDetail(t, m, "cli1")
	m = press(t, m, "E")
	ef, ok := topAny(m).(enrollFormModal)
	if !ok {
		t.Fatalf("E did not open the re-enroll form; top=%T", topAny(m))
	}
	if !ef.client {
		t.Error("client toggle not pre-set for a client-style peer")
	}
}

// TestReenrollNameNotEditable: the tab order skips the locked name field and
// typing never reaches it.
func TestReenrollNameNotEditable(t *testing.T) {
	dataDir, d := seedReenrollTUIEnv(t)
	m := actionModel(t, dataDir, d)
	m = openPeerDetail(t, m, "alpha")
	m = press(t, m, "E")

	for i := 0; i < 2*efCount; i++ {
		ef := topAny(m).(enrollFormModal)
		if ef.field == efName {
			t.Fatal("tab order reached the locked name field")
		}
		m = press(t, m, "tab")
	}
	for i := 0; i < 2*efCount; i++ {
		ef := topAny(m).(enrollFormModal)
		if ef.field == efName {
			t.Fatal("shift+tab order reached the locked name field")
		}
		m = press(t, m, "shift+tab")
	}
	m = typeRunes(m, "zzz")
	ef := topAny(m).(enrollFormModal)
	if got := strings.TrimSpace(ef.name.Value()); got != "alpha" {
		t.Fatalf("name mutated to %q, want alpha", got)
	}
	if ef.validateName() != "" {
		t.Fatalf("re-enroll validateName = %q, want always valid", ef.validateName())
	}
}

// TestReenrollSubmitStagesMint: submitting the untouched pre-filled form runs
// the MintEnroll upsert — result screen with the re-enroll copy, a staged
// token whose groups keep the hidden manager principal, and a peer row that is
// untouched until redemption.
func TestReenrollSubmitStagesMint(t *testing.T) {
	dataDir, d := seedReenrollTUIEnv(t)
	ctx := context.Background()
	before, err := d.GetPeer(ctx, "alpha")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	m := actionModel(t, dataDir, d)
	m = openPeerDetail(t, m, "alpha")
	m = press(t, m, "E")

	m = gotoField(m, efSubmit)
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd)

	res, ok := topAny(m).(enrollResultModal)
	if !ok {
		t.Fatalf("re-enroll did not land on the result screen; top=%T (%+v)", topAny(m), topAny(m))
	}
	if !res.reenroll || res.peer != "alpha" {
		t.Fatalf("result = reenroll=%v peer=%q, want re-enroll of alpha", res.reenroll, res.peer)
	}
	v := strings.Join(res.view(100, 30), "\n")
	if !strings.Contains(v, "nothing changes on the peer until this one-liner runs on it") {
		t.Fatalf("result screen missing the re-enroll semantics note:\n%s", v)
	}

	// The mint left the peer row byte-identical.
	after, err := d.GetPeer(ctx, "alpha")
	if err != nil {
		t.Fatalf("GetPeer after mint: %v", err)
	}
	if string(after.AuthorizedKey) != string(before.AuthorizedKey) || after.Serial != before.Serial ||
		after.PullToken != before.PullToken || after.Inbound != before.Inbound {
		t.Fatalf("peer row changed by the TUI mint:\nbefore %+v\nafter  %+v", before, after)
	}

	// The staged token carries the pre-checked groups PLUS the hidden manager
	// principal (preserved by the submit, not offered in the picker).
	tok := strings.TrimSuffix(strings.TrimPrefix(res.oneLiner, "curl -kfsSL https://certhold.home.lan/enroll/"), ".sh | bash")
	_, groupsCSV, targetUser, _, err := d.LookupToken(ctx, tok)
	if err != nil {
		t.Fatalf("LookupToken: %v", err)
	}
	if !strings.Contains(groupsCSV, "infra") || !strings.Contains(groupsCSV, "manager") {
		t.Fatalf("token groups = %q, want infra AND the preserved hidden manager", groupsCSV)
	}
	if targetUser != "alice" {
		t.Fatalf("token target_user = %q, want alice", targetUser)
	}

	// Redeeming commits: allowed keeps the hidden manager entry too.
	if _, _, _, _, err := d.ConsumeToken(ctx, tok); err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	allowed, err := d.GetPeerAllowedGroups(ctx, "alpha")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	if !isMember(allowed, "manager") || !isMember(allowed, "infra") {
		t.Fatalf("allowed after commit = %v, want infra + preserved manager", allowed)
	}
}

// TestReenrollSelfRowRefused: E on the manager's own detail page refuses with
// a footer notice (no modal), cleared by the next keypress.
func TestReenrollSelfRowRefused(t *testing.T) {
	dataDir, d := seedReenrollTUIEnv(t)
	m := actionModel(t, dataDir, d)
	m = openPeerDetail(t, m, selfRowName)
	m = press(t, m, "E")
	if _, ok := m.topModal(); ok {
		t.Fatalf("self-row E opened a modal; top=%T", topAny(m))
	}
	if !strings.Contains(m.notice, "certhold's own row") || !strings.Contains(m.notice, selfRowName) {
		t.Fatalf("notice = %q, want the self-row refusal", m.notice)
	}
	m = press(t, m, "j")
	if m.notice != "" {
		t.Fatalf("notice not cleared by the next keypress: %q", m.notice)
	}
}

// TestReenrollRevokedRefused: E on a revoked peer's detail page refuses with a
// footer notice.
func TestReenrollRevokedRefused(t *testing.T) {
	dataDir, d := seedReenrollTUIEnv(t)
	m := actionModel(t, dataDir, d)
	m = openPeerDetail(t, m, "revd")
	m = press(t, m, "E")
	if _, ok := m.topModal(); ok {
		t.Fatalf("revoked-peer E opened a modal; top=%T", topAny(m))
	}
	if !strings.Contains(m.notice, "revoked") || !strings.Contains(m.notice, "revd") {
		t.Fatalf("notice = %q, want the revoked refusal", m.notice)
	}
}

// TestReenrollReadOnlyGated: --read-only makes E a silent no-op on the detail
// page (no modal, no notice).
func TestReenrollReadOnlyGated(t *testing.T) {
	dataDir, d := seedReenrollTUIEnv(t)
	m := readOnlyModel(t, dataDir, d)
	m = openPeerDetail(t, m, "alpha")
	m = press(t, m, "E")
	if _, ok := m.topModal(); ok {
		t.Fatalf("read-only E opened a modal; top=%T", topAny(m))
	}
	if m.notice != "" {
		t.Fatalf("read-only E left a notice: %q", m.notice)
	}
}

// TestReenrollDetailHint: the detail-pane hint line advertises E only when
// mutations are enabled.
func TestReenrollDetailHint(t *testing.T) {
	dataDir, d := seedReenrollTUIEnv(t)
	m := actionModel(t, dataDir, d)
	m = openPeerDetail(t, m, "alpha")
	if v := m.View(); !strings.Contains(v, "E re-enroll") {
		t.Fatalf("detail hint line missing 'E re-enroll':\n%s", v)
	}
	ro := readOnlyModel(t, dataDir, d)
	ro = openPeerDetail(t, ro, "alpha")
	if v := ro.View(); strings.Contains(v, "E re-enroll") {
		t.Fatalf("read-only detail hint advertises E:\n%s", v)
	}
}

func readOnlyModel(t *testing.T, dataDir string, d *db.DB) Model {
	t.Helper()
	reload := func(ctx context.Context) (fleetData, error) {
		return load(ctx, d, dataDir+"/state.db")
	}
	data, _ := reload(context.Background())
	m := NewModel(context.Background(), data, reload)
	m.readOnly = true
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	return nm.(Model)
}
