package tui

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/shudza/certhold/internal/db"
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
	if !strings.Contains(strings.Join(ef.view(80), "\n"), "required") {
		t.Fatalf("empty-name form omits the required note:\n%s", strings.Join(ef.view(80), "\n"))
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
