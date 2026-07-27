package tui

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/ops"
	"github.com/shudza/certhold/internal/peerfiles"
)

// seedManagerEnv mirrors seedActionEnv's fleet (alpha in infra/db, beta in
// infra, groups infra/db/ops) and adds the reserved manager group exactly as a
// real fleet carries it: the group row exists (init seeds it), alpha is the
// manager's own peer row and allows inbound from it, and beta was CLI-enrolled
// with `--groups manager` so it holds the principal as a membership. The CA is
// plaintext so these flows never pay the KDF — the passphrase bridge is not what
// they exercise, and a batch of encrypted-CA unlocks under -race outruns drain's
// deadline on a loaded machine.
func seedManagerEnv(t *testing.T) (string, *db.DB) {
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
	for _, g := range []string{"infra", "db", "ops", peerfiles.ManagerPrincipal} {
		if err := d.EnsureGroup(ctx, g); err != nil {
			t.Fatalf("EnsureGroup %s: %v", g, err)
		}
	}
	for _, name := range []string{"alpha", "beta"} {
		_, pubAuth, sshPub, err := ca.GeneratePeerKey()
		if err != nil {
			t.Fatalf("GeneratePeerKey %s: %v", name, err)
		}
		if err := d.InsertPeer(ctx, name, 100, ssh.FingerprintSHA256(sshPub), pubAuth, "root", true, ""); err != nil {
			t.Fatalf("InsertPeer %s: %v", name, err)
		}
	}
	if err := d.SetPeerGroups(ctx, "alpha", []string{"infra", "db"}); err != nil {
		t.Fatalf("SetPeerGroups alpha: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "alpha", []string{"infra", peerfiles.ManagerPrincipal}); err != nil {
		t.Fatalf("SetPeerAllowedGroups alpha: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "beta", []string{"infra", peerfiles.ManagerPrincipal}); err != nil {
		t.Fatalf("SetPeerGroups beta: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "beta", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups beta: %v", err)
	}
	if err := d.BumpFleetRev(ctx); err != nil {
		t.Fatalf("BumpFleetRev: %v", err)
	}
	return dataDir, d
}

func peerAllowedSorted(t *testing.T, d *db.DB, name string) []string {
	t.Helper()
	a, err := d.GetPeerAllowedGroups(context.Background(), name)
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups %s: %v", name, err)
	}
	sort.Strings(a)
	return a
}

func assertNoManagerOption(t *testing.T, where string, opts []string) {
	t.Helper()
	for _, o := range opts {
		if o == peerfiles.ManagerPrincipal {
			t.Fatalf("%s: options offer the reserved manager group: %v", where, opts)
		}
	}
	if !isMember(opts, "infra") {
		t.Fatalf("%s: options lost the real groups: %v", where, opts)
	}
}

// TestEnrollFormHidesManagerGroup: both enroll pickers (membership + allowed
// inbound) omit the reserved manager group while the fleet has one.
func TestEnrollFormHidesManagerGroup(t *testing.T) {
	dataDir, d := seedManagerEnv(t)
	m := actionModel(t, dataDir, d)

	if !fleetHasManagerGroup(m) {
		t.Fatal("seed did not put a manager group in the fleet data")
	}
	_, ef := openEnroll(t, m)
	assertNoManagerOption(t, "enroll groups", ef.groupOpts)
	assertNoManagerOption(t, "enroll allowed", ef.allowOpts)
}

// TestEditGroupsHidesManagerGroup: the single-peer and batch (marked) edit-groups
// pickers both omit the reserved group.
func TestEditGroupsHidesManagerGroup(t *testing.T) {
	dataDir, d := seedManagerEnv(t)

	single := actionModel(t, dataDir, d)
	single = press(t, single, "u")
	pick, ok := topAny(single).(pickModal)
	if !ok {
		t.Fatalf("u did not open pick modal; top=%T", topAny(single))
	}
	assertNoManagerOption(t, "edit groups", pick.options)

	batch := batchModel(t, dataDir, d)
	batch = markPeer(t, batch, "beta")
	batch = press(t, batch, "u")
	bpick, ok := topAny(batch).(pickModal)
	if !ok || batch.batchKind != batchEditGroups {
		t.Fatalf("u with a mark did not open batch pick; top=%T kind=%v", topAny(batch), batch.batchKind)
	}
	assertNoManagerOption(t, "batch edit groups", bpick.options)
}

// TestEditAllowedHidesManagerGroup: the allowed-inbound picker omits the
// reserved group even for the manager's own peer row, which allows it.
func TestEditAllowedHidesManagerGroup(t *testing.T) {
	dataDir, d := seedManagerEnv(t)
	m := actionModel(t, dataDir, d)

	m = selectPeer(t, m, "alpha")
	m = press(t, m, "i")
	pick, ok := topAny(m).(pickModal)
	if !ok || pick.kind != pickPeerAllowed {
		t.Fatalf("i did not open allowed pick; top=%T", topAny(m))
	}
	assertNoManagerOption(t, "edit allowed", pick.options)
}

// TestEditGroupsKeepsHiddenManagerMembership: beta holds the manager principal
// from a CLI enroll. Toggling an unrelated group in the picker must not strip it
// — the picker can neither grant nor revoke the hidden principal.
func TestEditGroupsKeepsHiddenManagerMembership(t *testing.T) {
	dataDir, d := seedManagerEnv(t)
	m := actionModel(t, dataDir, d)

	m = selectPeer(t, m, "beta")
	m = press(t, m, "u")
	pick, ok := topAny(m).(pickModal)
	if !ok {
		t.Fatalf("u did not open pick modal; top=%T", topAny(m))
	}
	if pick.options[0] != "db" {
		t.Fatalf("options[0] = %q, want db (manager filtered out)", pick.options[0])
	}
	m = press(t, m, " ") // check db
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd)

	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("edit groups not done-ok: %+v", topAny(m))
	}
	if g := peerGroupsSorted(t, d, "beta"); strings.Join(g, ",") != "db,infra,manager" {
		t.Fatalf("beta groups = %v, want [db infra manager] (hidden manager preserved)", g)
	}
}

// TestEditAllowedKeepsHiddenManagerEntry: alpha (the manager's own row) allows
// inbound from the manager principal. Adding an unrelated group must keep it, or
// the manager loses access to its own peer.
func TestEditAllowedKeepsHiddenManagerEntry(t *testing.T) {
	dataDir, d := seedManagerEnv(t)
	rec := &recDial{}
	m := recModel(t, dataDir, d, rec)
	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("1")}) // peers view
	m = selectPeer(t, nm.(Model), "alpha")

	m = press(t, m, "i")
	pick, ok := topAny(m).(pickModal)
	if !ok || pick.kind != pickPeerAllowed {
		t.Fatalf("i did not open allowed pick; top=%T", topAny(m))
	}
	if pick.options[0] != "db" {
		t.Fatalf("options[0] = %q, want db (manager filtered out)", pick.options[0])
	}
	m = press(t, m, " ") // check db
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd)

	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("allowed edit not done-ok: %+v", topAny(m))
	}
	if a := peerAllowedSorted(t, d, "alpha"); strings.Join(a, ",") != "db,infra,manager" {
		t.Fatalf("alpha allowed = %v, want [db infra manager] (hidden manager preserved)", a)
	}
}

// TestBatchEditGroupsKeepsManagerPerPeer: an absolute batch assignment over two
// marked peers keeps the manager principal on the peer that already had it (beta)
// and never grants it to the peer that did not (alpha).
func TestBatchEditGroupsKeepsManagerPerPeer(t *testing.T) {
	dataDir, d := seedManagerEnv(t)
	m := batchModel(t, dataDir, d)

	m = markPeer(t, m, "alpha")
	m = markPeer(t, m, "beta")

	m = press(t, m, "u")
	pick, ok := topAny(m).(pickModal)
	if !ok || m.batchKind != batchEditGroups {
		t.Fatalf("u with marks did not open batch pick; top=%T kind=%v", topAny(m), m.batchKind)
	}
	// options sorted [db infra ops] (manager filtered out); cursor at db → j to
	// infra, j to ops, check ops only so the assignment is an absolute change.
	if strings.Join(pick.options, ",") != "db,infra,ops" {
		t.Fatalf("batch options = %v, want [db infra ops]", pick.options)
	}
	m = press(t, m, "j", "j", " ") // ops on
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd)

	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("batch edit-groups not done-ok: %+v", topAny(m))
	}
	if g := peerGroupsSorted(t, d, "beta"); strings.Join(g, ",") != "manager,ops" {
		t.Fatalf("beta groups = %v, want [manager ops] (hidden manager preserved)", g)
	}
	if g := peerGroupsSorted(t, d, "alpha"); strings.Join(g, ",") != "ops" {
		t.Fatalf("alpha groups = %v, want [ops] (must not gain manager)", g)
	}
}

// groupsModel is an action model parked on the groups view.
func groupsModel(t *testing.T, dataDir string, d *db.DB) Model {
	t.Helper()
	m := actionModel(t, dataDir, d)
	return press(t, m, "2")
}

// pickGroup rewinds to the first group row before selecting, so a test can move
// the cursor back up to a row above the current one.
func pickGroup(t *testing.T, m Model, name string) Model {
	t.Helper()
	for i := 0; i < len(m.data.Groups)+2; i++ {
		m = press(t, m, "k")
	}
	return selectGroup(t, m, name)
}

func assertReservedRefusal(t *testing.T, m Model, key string) {
	t.Helper()
	if len(m.modals) != 0 {
		t.Fatalf("%s on the manager row opened a modal: %T", key, topAny(m))
	}
	if !strings.Contains(m.notice, "reserved") || !strings.Contains(m.notice, peerfiles.ManagerPrincipal) {
		t.Fatalf("%s on the manager row left notice %q, want a reserved-group refusal", key, m.notice)
	}
	if !strings.Contains(m.View(), "reserved") {
		t.Fatalf("%s refusal is not rendered in the frame", key)
	}
}

// TestGroupMembersRefusedOnManagerRow: m on the reserved group's row opens no
// picker and flashes why; an ordinary row still opens the members picker, and
// the reserved row stays listed with its real membership untouched.
func TestGroupMembersRefusedOnManagerRow(t *testing.T) {
	dataDir, d := seedManagerEnv(t)
	m := groupsModel(t, dataDir, d)

	m = pickGroup(t, m, peerfiles.ManagerPrincipal)
	m = press(t, m, "m")
	assertReservedRefusal(t, m, "m")
	if m.batchKind != batchNone {
		t.Fatalf("refused m armed a batch: kind=%v", m.batchKind)
	}
	if mem := groupMembers(t, d, peerfiles.ManagerPrincipal); strings.Join(mem, ",") != "beta" {
		t.Fatalf("manager members = %v, want [beta] (refusal must not touch the DB)", mem)
	}

	m = pickGroup(t, m, "infra")
	m = press(t, m, "m")
	pick, ok := topAny(m).(pickModal)
	if !ok || pick.kind != pickGroupMembers {
		t.Fatalf("m on an ordinary group did not open the members picker; top=%T", topAny(m))
	}
	if m.notice != "" {
		t.Fatalf("notice %q survived the next keypress", m.notice)
	}
}

// TestGroupMembersRefusedOnManagerRowWithMarks: the marked-peers variant is
// refused too, and the refusal neither consumes the marks nor arms the batch —
// the operator can aim the same marked set at a real group.
func TestGroupMembersRefusedOnManagerRowWithMarks(t *testing.T) {
	dataDir, d := seedManagerEnv(t)
	m := batchModel(t, dataDir, d)
	m = markPeer(t, m, "alpha")
	m = markPeer(t, m, "beta")

	m = press(t, m, "2")
	m = pickGroup(t, m, peerfiles.ManagerPrincipal)
	m = press(t, m, "m")
	assertReservedRefusal(t, m, "m (marked)")
	if m.batchKind != batchNone {
		t.Fatalf("refused batch m armed a batch: kind=%v", m.batchKind)
	}
	if len(m.markedNames()) != 2 {
		t.Fatalf("marks after refusal = %v, want alpha+beta kept", m.markedNames())
	}

	m = pickGroup(t, m, "infra")
	m = press(t, m, "m")
	if _, ok := topAny(m).(pickModal); !ok || m.batchKind != batchMembers {
		t.Fatalf("kept marks did not drive a batch on an ordinary group; top=%T kind=%v", topAny(m), m.batchKind)
	}
}

// TestGroupRenameDeleteRefusedOnManagerRow: R and D on the reserved row refuse
// in the TUI (ops would reject them anyway) instead of walking the operator
// through a name entry or a confirm that can only fail.
func TestGroupRenameDeleteRefusedOnManagerRow(t *testing.T) {
	dataDir, d := seedManagerEnv(t)
	m := groupsModel(t, dataDir, d)
	m = pickGroup(t, m, peerfiles.ManagerPrincipal)

	m = press(t, m, "R")
	assertReservedRefusal(t, m, "R")
	m = press(t, m, "D")
	assertReservedRefusal(t, m, "D")

	if !groupExists(t, d, peerfiles.ManagerPrincipal) {
		t.Fatal("manager group vanished from the DB")
	}
	if !fleetHasManagerGroup(m) {
		t.Fatal("manager group is no longer listed in the groups view")
	}

	m = pickGroup(t, m, "infra")
	m = press(t, m, "R")
	if _, ok := topAny(m).(textModal); !ok {
		t.Fatalf("R on an ordinary group did not open the rename modal; top=%T", topAny(m))
	}
	m = press(t, m, "esc")
	m = press(t, m, "D")
	if _, ok := topAny(m).(confirmModal); !ok {
		t.Fatalf("D on an ordinary group did not open the delete confirm; top=%T", topAny(m))
	}
}

func fleetHasManagerGroup(m Model) bool {
	for _, g := range m.data.Groups {
		if g.Name == peerfiles.ManagerPrincipal {
			return true
		}
	}
	return false
}
