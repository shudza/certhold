package tui

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/ops"
)

// seedThreePeers extends seedActionEnv with a third inbound peer "mid" so a
// batch over three marked peers (with the middle injected-failing) has a real
// target set. Returns dataDir, db, CA passphrase; peers are alpha, beta, mid all
// inbound members of infra.
func seedThreePeers(t *testing.T) (string, *db.DB, string) {
	t.Helper()
	dataDir, d, pass := seedActionEnv(t)
	ctx := context.Background()
	_, pubAuth, sshPub, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey mid: %v", err)
	}
	if err := d.InsertPeer(ctx, "mid", 100, ssh.FingerprintSHA256(sshPub), pubAuth, "root", true, ""); err != nil {
		t.Fatalf("InsertPeer mid: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "mid", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerGroups mid: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "mid", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups mid: %v", err)
	}
	if err := d.BumpFleetRev(ctx); err != nil {
		t.Fatalf("BumpFleetRev: %v", err)
	}
	return dataDir, d, pass
}

// markPeer moves the cursor onto the named peer and presses space to mark it.
// It rewinds to the top first so it can reach a peer above the current cursor.
func markPeer(t *testing.T, m Model, name string) Model {
	t.Helper()
	for i := 0; i < len(m.filteredPeers())+2; i++ {
		m = press(t, m, "k")
	}
	for i := 0; i < len(m.filteredPeers())+2; i++ {
		if p, ok := m.selectedPeer(); ok && p.Name == name {
			return press(t, m, " ")
		}
		m = press(t, m, "j")
	}
	t.Fatalf("peer %q not selectable to mark", name)
	return m
}

// batchModel builds an action model already switched to the peers view.
func batchModel(t *testing.T, dataDir string, d *db.DB) Model {
	t.Helper()
	m := actionModel(t, dataDir, d)
	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("1")}) // peers view
	return nm.(Model)
}

// TestRevokeConfirmCopyClearDeleteSemantics is a regression guard for the T142
// redesign: the default revoke path SSHes in, strips certhold, and hard-deletes
// the row — it rotates nothing. The confirm modals must say so. Asserts both the
// single- and batch-revoke confirm bodies use clear+delete wording and never
// mention "rekey"/"rotate", so the operator-facing copy can't silently drift
// back to the old CA-rekey description.
func TestRevokeConfirmCopyClearDeleteSemantics(t *testing.T) {
	dataDir, d, _ := seedThreePeers(t)

	// Single-peer path: alpha selected, no marks.
	single := batchModel(t, dataDir, d)
	single = press(t, single, "x")
	cm, ok := topAny(single).(confirmModal)
	if !ok {
		t.Fatalf("single: x did not open confirm; top=%T", topAny(single))
	}
	body := strings.Join(cm.body, "\n")
	if !strings.Contains(body, "Clear certhold off alpha over SSH and delete its row?") {
		t.Fatalf("single confirm missing clear+delete wording:\n%s", body)
	}
	if !strings.Contains(body, "This does not rotate the CA.") {
		t.Fatalf("single confirm missing no-rotation line:\n%s", body)
	}
	if strings.Contains(body, "rekey") || strings.Contains(body, "rotates the CA") {
		t.Fatalf("single confirm still mentions CA rekey/rotation:\n%s", body)
	}

	// Batch path: mark one live peer.
	batch := batchModel(t, dataDir, d)
	batch = markPeer(t, batch, "mid")
	batch = press(t, batch, "x")
	bcm, ok := topAny(batch).(confirmModal)
	if !ok || batch.batchKind != batchRevoke {
		t.Fatalf("batch: x with a mark did not open batch confirm; top=%T kind=%v", topAny(batch), batch.batchKind)
	}
	bbody := strings.Join(bcm.body, "\n")
	if !strings.Contains(bbody, "Clear certhold off 1 peers over SSH and delete each? (Does not rotate the CA.)") {
		t.Fatalf("batch confirm missing clear+delete wording:\n%s", bbody)
	}
	if strings.Contains(bbody, "rekey") {
		t.Fatalf("batch confirm still mentions CA rekey:\n%s", bbody)
	}
}

// TestBatchRevokeMiddleFailsContinues is the headline AC: three marked peers, the
// middle injected to fail, the batch continues, the summary reads 2 ok / 1
// failed, the failed peer keeps its mark while the others are cleared, and the
// two succeeded peers are revoked in the db.
//
// The per-peer op here applies the db-side revoke (SetPeerRevoked) for the
// successes and errors on the middle peer. This deliberately exercises the batch
// ORCHESTRATION (sequential, continue-on-error, aggregated progress + summary,
// mark retention/clearing, db effect) without re-running ops.RevokePeer's whole
// CA rekey three times in one wall-clock second — the rekey's second-resolution
// `ca.old.<ts>` backup directory collides on back-to-back runs, an ops-level
// constraint outside T05's scope. ops.RevokePeer's full path is covered by the
// single-peer TestRevokeFlow and TestSinglePeerUnchangedWhenNoMarks below.
func TestBatchRevokeMiddleFailsContinues(t *testing.T) {
	dataDir, d, pass := seedThreePeers(t)
	m := batchModel(t, dataDir, d)

	m = markPeer(t, m, "alpha")
	m = markPeer(t, m, "beta")
	m = markPeer(t, m, "mid")
	if len(m.marks) != 3 {
		t.Fatalf("expected 3 marks, got %d", len(m.marks))
	}

	op := func(ctx context.Context, deps ops.Deps, name string) error {
		if name == "beta" { // the middle target by data order alpha,beta,mid
			return errors.New("injected failure")
		}
		return deps.DB.SetPeerRevoked(ctx, name)
	}
	nm, cmd := m.startBatch("revoke", m.markedNames(), op)
	m = drain(t, nm.(Model), cmd, pass)

	pg, ok := topAny(m).(progressModal)
	if !ok || !pg.done {
		t.Fatalf("expected done progress modal, got %+v", topAny(m))
	}
	if pg.err == nil {
		t.Fatal("batch with one failed peer must surface an error summary")
	}
	tr := strings.Join(pg.lines, "\n")
	if !strings.Contains(tr, "✓ revoke alpha") || !strings.Contains(tr, "✓ revoke mid") {
		t.Fatalf("transcript missing the succeeded peers:\n%s", tr)
	}
	if !strings.Contains(tr, "✗ beta") || !strings.Contains(tr, "injected failure") {
		t.Fatalf("transcript missing the failed peer line:\n%s", tr)
	}
	if !strings.Contains(tr, "2 ok, 1 failed") {
		t.Fatalf("transcript missing the aggregate summary:\n%s", tr)
	}

	// Failed peer keeps its mark; the two succeeded peers are cleared.
	if len(m.marks) != 1 || !m.marks["beta"] {
		t.Fatalf("expected only beta to stay marked, got %v", m.marks)
	}

	// db state matches: alpha + mid revoked, beta NOT revoked (its op failed).
	for _, name := range []string{"alpha", "mid"} {
		p, err := d.GetPeer(context.Background(), name)
		if err != nil {
			t.Fatalf("GetPeer %s: %v", name, err)
		}
		if !p.Revoked {
			t.Fatalf("db: %s not revoked after successful batch op", name)
		}
	}
	if p, _ := d.GetPeer(context.Background(), "beta"); p.Revoked {
		t.Fatal("db: beta revoked despite its op failing")
	}
}

// TestBatchRevokeRealOpsSingleTarget drives the real x → confirm → batch path
// end to end with a one-peer marked set so the default ops.RevokePeer
// (clear+delete) runs for real through the batch wrapper: the summary is
// 1 ok / 0 failed, the mark clears, and the db row is deleted.
func TestBatchRevokeRealOpsSingleTarget(t *testing.T) {
	dataDir, d, pass := seedThreePeers(t)
	m := batchModel(t, dataDir, d)

	m = markPeer(t, m, "mid")

	m = press(t, m, "x")
	cm, ok := topAny(m).(confirmModal)
	if !ok || m.batchKind != batchRevoke {
		t.Fatalf("x with a mark did not open batch confirm; top=%T kind=%v", topAny(m), m.batchKind)
	}
	if !strings.Contains(strings.Join(cm.body, "\n"), "mid") {
		t.Fatalf("batch confirm body omits target:\n%s", strings.Join(cm.body, "\n"))
	}
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = drain(t, nm.(Model), cmd, pass)

	pg, ok := topAny(m).(progressModal)
	if !ok || !pg.done || pg.err != nil {
		t.Fatalf("batch revoke not done-ok: %+v", topAny(m))
	}
	if !strings.Contains(strings.Join(pg.lines, "\n"), "1 ok, 0 failed") {
		t.Fatalf("transcript missing 1 ok summary:\n%s", strings.Join(pg.lines, "\n"))
	}
	if len(m.marks) != 0 {
		t.Fatalf("fully-succeeded batch must clear all marks, got %v", m.marks)
	}
	if _, err := d.GetPeer(context.Background(), "mid"); !errors.Is(err, db.ErrPeerNotFound) {
		t.Fatalf("db: mid row should be deleted by the real-ops batch, got err=%v", err)
	}
	if _, err := d.GetPeer(context.Background(), "alpha"); err != nil {
		t.Fatalf("db: unmarked alpha was affected by the batch: %v", err)
	}
}

// TestBatchEditGroupsAcrossMarked marks two peers and assigns a group set via u;
// both peers' db groups become exactly the chosen set.
func TestBatchEditGroupsAcrossMarked(t *testing.T) {
	dataDir, d, pass := seedThreePeers(t)
	m := batchModel(t, dataDir, d)

	m = markPeer(t, m, "alpha")
	m = markPeer(t, m, "beta")

	m = press(t, m, "u")
	pick, ok := topAny(m).(pickModal)
	if !ok {
		t.Fatalf("u with marks did not open pick modal; top=%T", topAny(m))
	}
	if m.batchKind != batchEditGroups {
		t.Fatalf("batchKind = %v, want batchEditGroups", m.batchKind)
	}
	// Pre-checked empty (absolute assignment). options sorted [db infra ops]; check infra+ops.
	// cursor at db; move to infra, toggle; move to ops, toggle.
	if pick.options[0] != "db" {
		t.Fatalf("options[0] = %q, want db", pick.options[0])
	}
	m = press(t, m, "j", " ") // infra on
	m = press(t, m, "j", " ") // ops on
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd, pass)

	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("batch edit-groups not done-ok: %+v", topAny(m))
	}
	for _, name := range []string{"alpha", "beta"} {
		if g := peerGroupsSorted(t, d, name); strings.Join(g, ",") != "infra,ops" {
			t.Fatalf("%s groups = %v, want [infra ops]", name, g)
		}
	}
	if len(m.marks) != 0 {
		t.Fatalf("succeeded batch edit-groups must clear marks, got %v", m.marks)
	}
}

// TestBatchMembersAssignsMarkedToGroup marks two peers in peers view, switches to
// groups view, selects a group, presses m, and confirms the picker's union; both
// marked peers gain the group.
func TestBatchMembersAssignsMarkedToGroup(t *testing.T) {
	dataDir, d, pass := seedThreePeers(t)
	m := batchModel(t, dataDir, d)

	// Mark beta + mid (neither is in group "db"); alpha is already in db.
	m = markPeer(t, m, "beta")
	m = markPeer(t, m, "mid")

	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("2")}) // groups view
	m = selectGroup(t, nm.(Model), "db")

	m = press(t, m, "m")
	pick, ok := topAny(m).(pickModal)
	if !ok || m.batchKind != batchMembers {
		t.Fatalf("m with marks did not open batch members pick; top=%T kind=%v", topAny(m), m.batchKind)
	}
	// Pre-checked = current members (alpha) ∪ marked (beta, mid).
	if !pick.checked["alpha"] || !pick.checked["beta"] || !pick.checked["mid"] {
		t.Fatalf("members pre-check missing the union: %+v", pick.checked)
	}
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd, pass)

	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("batch members not done-ok: %+v", topAny(m))
	}
	if mem := groupMembers(t, d, "db"); strings.Join(mem, ",") != "alpha,beta,mid" {
		t.Fatalf("db group members = %v, want [alpha beta mid]", mem)
	}
}

// TestMarksSurviveFilter marks a peer, applies a filter that hides it, then
// clears the filter: the mark is still on the peer (keyed by name, not row).
func TestMarksSurviveFilter(t *testing.T) {
	dataDir, d, _ := seedThreePeers(t)
	m := batchModel(t, dataDir, d)

	m = markPeer(t, m, "alpha")
	if !m.marks["alpha"] {
		t.Fatal("alpha not marked")
	}
	// Filter to "beta" — alpha is hidden from the view but its mark persists.
	m = press(t, m, "/")
	m = typeRunes(m, "beta")
	m = press(t, m, "enter")
	hidden := true
	for _, p := range m.filteredPeers() {
		if p.Name == "alpha" {
			hidden = false
		}
	}
	if !hidden {
		t.Fatal("filter did not hide alpha")
	}
	if !m.marks["alpha"] {
		t.Fatal("mark lost when the marked peer was filtered out")
	}
	// Clearing the filter brings alpha back, still marked.
	m = press(t, m, "esc")
	if m.filters[viewPeers] != "" {
		t.Fatal("esc did not clear the filter")
	}
	if !m.marks["alpha"] {
		t.Fatal("mark lost after filter cleared")
	}
}

// TestEscPrecedenceModalFilterMarks asserts the esc order: a modal closes first,
// then a filter clears, then marks clear — one esc each, never skipping a level.
func TestEscPrecedenceModalFilterMarks(t *testing.T) {
	dataDir, d, _ := seedThreePeers(t)
	m := batchModel(t, dataDir, d)

	m = markPeer(t, m, "alpha")
	// Apply a filter and open a modal on top.
	m = press(t, m, "/")
	m = typeRunes(m, "al")
	m = press(t, m, "enter")
	m = press(t, m, "u") // pick modal (single-peer alpha; marks are on alpha only)
	if _, ok := m.topModal(); !ok {
		t.Fatal("expected a modal open before esc precedence test")
	}

	// 1st esc: closes the modal; filter + marks untouched.
	m = press(t, m, "esc")
	if _, ok := m.topModal(); ok {
		t.Fatal("first esc did not close the modal")
	}
	if m.filters[viewPeers] == "" {
		t.Fatal("first esc cleared the filter instead of only the modal")
	}
	if !m.marks["alpha"] {
		t.Fatal("first esc cleared marks instead of only the modal")
	}

	// 2nd esc: clears the filter; marks untouched.
	m = press(t, m, "esc")
	if m.filters[viewPeers] != "" {
		t.Fatal("second esc did not clear the filter")
	}
	if !m.marks["alpha"] {
		t.Fatal("second esc cleared marks instead of only the filter")
	}

	// 3rd esc: clears the marks.
	m = press(t, m, "esc")
	if len(m.marks) != 0 {
		t.Fatalf("third esc did not clear marks: %v", m.marks)
	}
}

// TestSinglePeerUnchangedWhenNoMarks checks x/u with zero marks still drive the
// single selected peer (the v1 path), not a batch.
func TestSinglePeerUnchangedWhenNoMarks(t *testing.T) {
	dataDir, d, pass := seedThreePeers(t)
	m := batchModel(t, dataDir, d) // alpha selected, no marks

	m = press(t, m, "x")
	cm, ok := topAny(m).(confirmModal)
	if !ok {
		t.Fatalf("x did not open confirm; top=%T", topAny(m))
	}
	if cm.subject != "alpha" || m.batchKind != batchNone {
		t.Fatalf("no-mark x should target the single selected peer alpha; subject=%q kind=%v", cm.subject, m.batchKind)
	}
	if !strings.Contains(strings.Join(cm.body, "\n"), "Clear certhold off alpha") {
		t.Fatalf("single-peer confirm body wrong:\n%s", strings.Join(cm.body, "\n"))
	}
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = drain(t, nm.(Model), cmd, pass)
	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("single-peer revoke not done-ok: %+v", topAny(m))
	}
	if _, err := d.GetPeer(context.Background(), "alpha"); !errors.Is(err, db.ErrPeerNotFound) {
		t.Fatalf("db: alpha row should be deleted by the single-peer path, got err=%v", err)
	}
	if _, err := d.GetPeer(context.Background(), "beta"); err != nil {
		t.Fatalf("db: beta affected though only alpha was selected: %v", err)
	}
}

// TestBatchSkipsRevokedMarkedPeer marks a peer that is already revoked plus a
// live one; the batch revoke targets only the live peer.
func TestBatchSkipsRevokedMarkedPeer(t *testing.T) {
	dataDir, d, pass := seedThreePeers(t)
	if err := d.SetPeerRevoked(context.Background(), "beta"); err != nil {
		t.Fatalf("SetPeerRevoked beta: %v", err)
	}
	m := batchModel(t, dataDir, d)
	m = drainReload(t, m) // reload so beta shows revoked

	m = markPeer(t, m, "beta")  // revoked
	m = markPeer(t, m, "alpha") // live

	m = press(t, m, "x")
	cm, ok := topAny(m).(confirmModal)
	if !ok {
		t.Fatalf("x with marks did not open batch confirm; top=%T", topAny(m))
	}
	// confirm lists only the live target alpha.
	if strings.Contains(strings.Join(cm.body, "\n"), "beta") {
		t.Fatalf("batch confirm should omit the revoked beta:\n%s", strings.Join(cm.body, "\n"))
	}
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = drain(t, nm.(Model), cmd, pass)
	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("batch revoke not done-ok: %+v", topAny(m))
	}
}

// drainReload runs a pending reloadCmd-style update synchronously: it reloads
// once so the model's data reflects the latest db. Used where a test needs the
// reloaded snapshot before driving keys.
func drainReload(t *testing.T, m Model) Model {
	t.Helper()
	data, err := m.reload(context.Background())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	nm, _ := m.Update(reloadedMsg{data: data})
	return nm.(Model)
}

// TestReadOnlyBlocksBatch checks marks + a batch key open no modal under
// --read-only (space itself may mark, but no mutation launches).
func TestReadOnlyBlocksBatch(t *testing.T) {
	dataDir, d, _ := seedThreePeers(t)
	reload := func(ctx context.Context) (fleetData, error) {
		return load(ctx, d, filepath.Join(dataDir, "state.db"))
	}
	data, _ := reload(context.Background())
	m := NewModel(context.Background(), data, reload)
	m.readOnly = true
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = nm.(Model)

	m = markPeer(t, m, "alpha")
	m = markPeer(t, m, "beta")
	for _, k := range []string{"x", "u"} {
		if mm := press(t, m, k); func() bool { _, ok := mm.topModal(); return ok }() {
			t.Fatalf("read-only: batch key %q opened a modal", k)
		}
	}
}

// markedRows builds a peers-view model with two marked peers for the render
// snapshots below.
func markedRowsModel(t *testing.T) Model {
	t.Helper()
	m := newTestModel(nil)
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = nm.(Model)
	m = markPeer(t, m, "alpha")
	m = markPeer(t, m, "gamma")
	return m
}

// TestMarkedRowsRenderTextualMarker asserts the marked rows carry the textual ▣
// glyph (NO_COLOR-safe) and the footer shows the count.
func TestMarkedRowsRenderTextualMarker(t *testing.T) {
	m := markedRowsModel(t)
	v := m.View()
	if !strings.Contains(v, markMarker+"alpha") && !strings.Contains(v, "▣ alpha") {
		t.Fatalf("alpha row missing the mark glyph:\n%s", v)
	}
	if !strings.Contains(v, "2 marked") {
		t.Fatalf("footer missing mark count:\n%s", v)
	}
}

// TestPickModalScrollsBoundedToHeight builds a pickModal with more options than
// fit a small height and asserts: the rendered body never exceeds the budget,
// the scroll cue shows, the cursor stays visible as it descends, the LAST option
// becomes reachable, and toggling works while scrolled.
func TestPickModalScrollsBoundedToHeight(t *testing.T) {
	opts := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		opts = append(opts, fmt.Sprintf("grp%02d", i))
	}
	pm := newPickModal("pick groups", "alpha", opts, nil)

	const h = 8 // body budget (post-border), like modalFrame passes
	bodyHas := func(p pickModal, s string) bool {
		return strings.Contains(strings.Join(p.view(60, h), "\n"), s)
	}

	// At the top: bounded, cue present, first option shown, last hidden.
	body := pm.view(60, h)
	if len(body) > h {
		t.Fatalf("pick body %d lines exceeds height %d:\n%s", len(body), h, strings.Join(body, "\n"))
	}
	if !bodyHas(pm, "▼") {
		t.Fatalf("overflowing pick missing down cue:\n%s", strings.Join(body, "\n"))
	}
	if !bodyHas(pm, "grp00") {
		t.Fatalf("top of pick missing first option:\n%s", strings.Join(body, "\n"))
	}
	if bodyHas(pm, "grp19") {
		t.Fatalf("last option should be off-screen at top:\n%s", strings.Join(body, "\n"))
	}

	// Drive the cursor to the bottom; the body stays bounded the whole way and the
	// cursor row stays rendered.
	for i := 0; i < 19; i++ {
		next, _ := pm.handle(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
		pm = next.(pickModal)
		b := pm.view(60, h)
		if len(b) > h {
			t.Fatalf("pick body exceeded height while scrolling (cursor %d):\n%s", pm.cursor, strings.Join(b, "\n"))
		}
		if !strings.Contains(strings.Join(b, "\n"), opts[pm.cursor]) {
			t.Fatalf("cursor option %q not visible at cursor %d:\n%s", opts[pm.cursor], pm.cursor, strings.Join(b, "\n"))
		}
	}
	if pm.cursor != 19 {
		t.Fatalf("cursor = %d, want 19 at bottom", pm.cursor)
	}
	if !bodyHas(pm, "grp19") {
		t.Fatalf("scrolled-down pick missing the last option:\n%s", strings.Join(pm.view(60, h), "\n"))
	}
	if !bodyHas(pm, "▲") {
		t.Fatalf("scrolled-down pick missing the up cue:\n%s", strings.Join(pm.view(60, h), "\n"))
	}

	// Toggle while scrolled: the checkbox flips for the bottom option.
	next, _ := pm.handle(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(" ")})
	pm = next.(pickModal)
	if !pm.checked["grp19"] {
		t.Fatalf("space did not toggle the scrolled-to option: %+v", pm.checked)
	}
	if !bodyHas(pm, "[x] grp19") {
		t.Fatalf("toggled option not rendered checked while scrolled:\n%s", strings.Join(pm.view(60, h), "\n"))
	}
}

// TestBatchConfirmClampsLongList builds a confirm body over many targets and
// asserts the "+N more" clamp fires and the list is capped at markMax entries.
func TestBatchConfirmClampsLongList(t *testing.T) {
	names := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		names = append(names, string(rune('a'+i))+"peer")
	}
	body := batchConfirmBody("Revoke 20 peers?", names)
	bullets := 0
	for _, l := range body {
		if strings.Contains(l, "•") {
			bullets++
		}
	}
	if bullets != markMax {
		t.Fatalf("clamped list should show %d bullets, got %d", markMax, bullets)
	}
	if !strings.Contains(strings.Join(body, "\n"), "+12 more") {
		t.Fatalf("missing +N more tail:\n%s", strings.Join(body, "\n"))
	}
}

// TestBatchWrongPassphraseRetriesWholeBatch checks a wrong CA passphrase on a
// batch aborts cleanly (no peer marked failed) and re-runs in place once the
// right one is entered — like the single-peer retry, not a per-peer reprompt
// storm. Marks survive the aborted attempt and clear on the retry.
//
// The op raises the CA prompt (deps.CAUnlock) then returns a passphrase-class
// error when the entered value is wrong, which is exactly what
// handleActionDone's retry branch keys on (isPassphraseError → Forget cache +
// relaunch). It is crypto-free and deterministic so it stays fast under -race
// (real ca.LoadWithPassphrase crypto over multiple targets is what made an
// earlier version flirt with drain's deadline under the race detector); the
// real-crypto retry is already covered by the single-peer TestWrongPassphraseRetry.
func TestBatchWrongPassphraseRetriesWholeBatch(t *testing.T) {
	dataDir, d, pass := seedThreePeers(t)
	m := batchModel(t, dataDir, d)
	m = markPeer(t, m, "alpha")

	op := func(ctx context.Context, deps ops.Deps, name string) error {
		b, err := deps.CAUnlock()
		if err != nil {
			return err
		}
		if string(b) != pass {
			return errors.New("load ca: x509: decryption password incorrect")
		}
		return deps.DB.SetPeerGroups(ctx, name, []string{"infra"})
	}
	nm, cmd := m.startBatch("update", m.markedNames(), op)
	// First answer wrong → passphrase-class error aborts the batch; the retry
	// branch forgets the bad cache and re-prompts; the correct answer completes it.
	m = drain(t, nm.(Model), cmd, "wrong", pass)

	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("batch retry did not complete: %+v", topAny(m))
	}
	if len(m.marks) != 0 {
		t.Fatalf("succeeded retry must clear marks, got %v", m.marks)
	}
	if g := peerGroupsSorted(t, d, "alpha"); strings.Join(g, ",") != "infra" {
		t.Fatalf("alpha groups after retry = %v, want [infra]", g)
	}
}

// TestNoGoroutineLeakAcrossBatches runs several full batch runs (each an
// injected mid-batch failure so the continue-on-error path is exercised) through
// the event loop and asserts NumGoroutine settles back to baseline. A batch is N
// sequential ops behind ONE progress + passphrase bridge, so the reader-cmd
// retirement invariant must hold across batches exactly as it does for single
// actions: each completed batch leaves one re-armed passphrase reader that the
// next batch's arm() retires, and close() retires the last. Settling is joined
// on a stable goroutine count (no fixed sleeps).
func TestNoGoroutineLeakAcrossBatches(t *testing.T) {
	dataDir, d, pass := seedThreePeers(t)
	m := batchModel(t, dataDir, d)
	m = markPeer(t, m, "alpha")
	m = markPeer(t, m, "beta")
	m = markPeer(t, m, "mid")

	settleGoroutines(t)
	base := runtime.NumGoroutine()

	// An op that fails the middle target every run; the failed peer keeps its
	// mark so the marked set is stable across iterations and each batch re-runs
	// the same three targets with one failure.
	op := func(ctx context.Context, deps ops.Deps, name string) error {
		if name == "beta" {
			return errors.New("injected mid-batch failure")
		}
		// Touch the CA unlocker so the passphrase bridge (and its reader-cmd
		// retirement across batches) is actually exercised, not just the event
		// bridge. The unlocker caches after the first prompt.
		if _, err := deps.CAUnlock(); err != nil {
			return err
		}
		return nil
	}

	const batches = 8
	answers := []string{pass} // only the first batch prompts for the CA passphrase
	for i := 0; i < batches; i++ {
		// Re-mark beta+the cleared successes so every batch has a 3-target set.
		m.marks = map[string]bool{"alpha": true, "beta": true, "mid": true}
		nm, cmd := m.startBatch("revoke", []string{"alpha", "beta", "mid"}, op)
		m = drain(t, nm.(Model), cmd, answers...)
		answers = nil // cached after the first
		pg, ok := topAny(m).(progressModal)
		if !ok || !pg.done {
			t.Fatalf("batch %d not done: %+v", i, topAny(m))
		}
		if !strings.Contains(strings.Join(pg.lines, "\n"), "2 ok, 1 failed") {
			t.Fatalf("batch %d summary wrong:\n%s", i, strings.Join(pg.lines, "\n"))
		}
		m = press(t, m, "esc") // dismiss the progress modal
	}

	m.pass.close()
	m.peerPass.Close()
	settleGoroutines(t)

	if got := runtime.NumGoroutine(); got > base {
		t.Fatalf("goroutine leak across %d batches: baseline=%d after=%d (delta=%d)",
			batches, base, got, got-base)
	}
}

// TestMarkedLayoutInvariants asserts the marker column preserves the v1 frame
// invariants at 80x24 and 60x12 under a forced ANSI256 profile: exact height,
// every line clamped to width.
func TestMarkedLayoutInvariants(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.ANSI256)
	defer lipgloss.SetColorProfile(prev)

	sawANSI := false
	for _, size := range []tea.WindowSizeMsg{{Width: 80, Height: 24}, {Width: 60, Height: 12}} {
		m := newTestModel(nil)
		nm, _ := m.Update(size)
		m = nm.(Model)
		m = markPeer(t, m, "alpha")
		m = markPeer(t, m, "gamma")
		v := m.View()
		if strings.Contains(v, "\x1b[") {
			sawANSI = true
		}
		lines := strings.Split(v, "\n")
		if len(lines) != size.Height {
			t.Fatalf("%dx%d: got %d lines, want %d", size.Width, size.Height, len(lines), size.Height)
		}
		for _, l := range lines {
			if lw := lipgloss.Width(l); lw > size.Width {
				t.Fatalf("%dx%d: line overflows (%d > %d): %q", size.Width, size.Height, lw, size.Width, l)
			}
		}
		// The mark glyph must be present in the rendered frame.
		if !strings.Contains(v, "▣") {
			t.Fatalf("%dx%d: marked frame missing the ▣ glyph:\n%s", size.Width, size.Height, v)
		}
	}
	if !sawANSI {
		t.Fatal("forced color profile produced no ANSI — overflow checks are vacuous")
	}
}
