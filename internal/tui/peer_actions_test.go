package tui

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
)

// selectPeer rewinds to the top of the peers table and steps down until the
// named peer is the selection. Mirrors markPeer's navigation but does not mark.
func selectPeer(t *testing.T, m Model, name string) Model {
	t.Helper()
	for i := 0; i < len(m.filteredPeers())+2; i++ {
		m = press(t, m, "k")
	}
	for i := 0; i < len(m.filteredPeers())+2; i++ {
		if p, ok := m.selectedPeer(); ok && p.Name == name {
			return m
		}
		m = press(t, m, "j")
	}
	t.Fatalf("peer %q not selectable", name)
	return m
}

// TestRemoveConfirmCopyNoPeerContact asserts the remove confirm spells out that
// it is a DB-only delete with no peer contact, and that it never reuses revoke's
// clear-over-SSH wording.
func TestRemoveConfirmCopyNoPeerContact(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	m := batchModel(t, dataDir, d)

	m = press(t, m, "X")
	cm, ok := topAny(m).(confirmModal)
	if !ok {
		t.Fatalf("X did not open confirm; top=%T", topAny(m))
	}
	if cm.kind != confirmRemove || cm.subject != "alpha" || m.batchKind != batchNone {
		t.Fatalf("remove confirm wrong: kind=%v subject=%q batch=%v", cm.kind, cm.subject, m.batchKind)
	}
	body := strings.Join(cm.body, "\n")
	if !strings.Contains(body, "No peer is contacted") {
		t.Fatalf("remove confirm missing no-peer-contact wording:\n%s", body)
	}
	if !strings.Contains(body, "manager DB only") {
		t.Fatalf("remove confirm missing DB-only wording:\n%s", body)
	}
	if strings.Contains(body, "Clear certhold off alpha over SSH") {
		t.Fatalf("remove confirm must not use revoke's clear-over-SSH copy:\n%s", body)
	}
}

// TestRemoveEscCancels checks esc on the remove confirm closes it without
// touching the db row.
func TestRemoveEscCancels(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	m := batchModel(t, dataDir, d)

	m = press(t, m, "X")
	if _, ok := topAny(m).(confirmModal); !ok {
		t.Fatalf("X did not open confirm; top=%T", topAny(m))
	}
	m = press(t, m, "esc")
	if _, ok := m.topModal(); ok {
		t.Fatal("esc did not close the remove confirm")
	}
	if _, err := d.GetPeer(context.Background(), "alpha"); err != nil {
		t.Fatalf("esc-canceled remove still deleted alpha: %v", err)
	}
}

// TestRemoveConfirmDeletesRowOnly drives X → y for real: ops.RemovePeer deletes
// the db row and no peer is dialed (the fake pusher would record nothing).
func TestRemoveConfirmDeletesRowOnly(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	m := batchModel(t, dataDir, d)

	m = press(t, m, "X")
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = drain(t, nm.(Model), cmd)

	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("remove not done-ok: %+v", topAny(m))
	}
	if _, err := d.GetPeer(context.Background(), "alpha"); err != db.ErrPeerNotFound {
		t.Fatalf("alpha row should be gone after remove, got err=%v", err)
	}
	if _, err := d.GetPeer(context.Background(), "beta"); err != nil {
		t.Fatalf("beta affected though only alpha was removed: %v", err)
	}
}

// TestBatchRemoveOverMarked marks two peers and removes them in one batch; both
// rows are deleted and the marked set clears.
func TestBatchRemoveOverMarked(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	m := batchModel(t, dataDir, d)

	m = markPeer(t, m, "alpha")
	m = markPeer(t, m, "beta")

	m = press(t, m, "X")
	cm, ok := topAny(m).(confirmModal)
	if !ok || cm.kind != confirmRemove || m.batchKind != batchRemove {
		t.Fatalf("X with marks did not open batch remove confirm; top=%T kind=%v batch=%v", topAny(m), cm.kind, m.batchKind)
	}
	if !strings.Contains(strings.Join(cm.body, "\n"), "No peer is contacted") {
		t.Fatalf("batch remove confirm missing no-peer-contact wording:\n%s", strings.Join(cm.body, "\n"))
	}
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = drain(t, nm.(Model), cmd)

	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("batch remove not done-ok: %+v", topAny(m))
	}
	for _, n := range []string{"alpha", "beta"} {
		if _, err := d.GetPeer(context.Background(), n); err != db.ErrPeerNotFound {
			t.Fatalf("%s row should be gone after batch remove, got err=%v", n, err)
		}
	}
	if len(m.marks) != 0 {
		t.Fatalf("succeeded batch remove must clear marks, got %v", m.marks)
	}
}

// TestEditAddressSetsNew submits a new address through the text modal; the db
// records it.
func TestEditAddressSetsNew(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	m := batchModel(t, dataDir, d)

	m = press(t, m, "a")
	tm, ok := topAny(m).(textModal)
	if !ok || tm.kind != textEditAddress || tm.subject != "alpha" {
		t.Fatalf("a did not open the edit-address text modal; top=%T", topAny(m))
	}
	m = typeRunes(m, "10.0.0.9")
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd)

	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("edit-address not done-ok: %+v", topAny(m))
	}
	p, err := d.GetPeer(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("GetPeer alpha: %v", err)
	}
	if p.Address != "10.0.0.9" {
		t.Fatalf("alpha Address = %q, want 10.0.0.9", p.Address)
	}
}

// TestEditAddressPrefillsCurrent seeds an address, opens the modal, and asserts
// the input is pre-filled with the current value.
func TestEditAddressPrefillsCurrent(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	if err := d.SetPeerAddress(context.Background(), "alpha", "1.2.3.4"); err != nil {
		t.Fatalf("SetPeerAddress: %v", err)
	}
	m := batchModel(t, dataDir, d)
	m = drainReload(t, m)
	m = selectPeer(t, m, "alpha")

	m = press(t, m, "a")
	tm, ok := topAny(m).(textModal)
	if !ok {
		t.Fatalf("a did not open the text modal; top=%T", topAny(m))
	}
	if tm.input.Value() != "1.2.3.4" {
		t.Fatalf("edit-address prefill = %q, want 1.2.3.4", tm.input.Value())
	}
}

// TestEditAddressEmptyClears submits an empty address against a peer that has
// one; ops.SetPeerAddress("") clears it (dial by name).
func TestEditAddressEmptyClears(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	if err := d.SetPeerAddress(context.Background(), "alpha", "1.2.3.4"); err != nil {
		t.Fatalf("SetPeerAddress: %v", err)
	}
	m := batchModel(t, dataDir, d)
	m = drainReload(t, m)
	m = selectPeer(t, m, "alpha")

	m = press(t, m, "a")
	if _, ok := topAny(m).(textModal); !ok {
		t.Fatalf("a did not open the text modal; top=%T", topAny(m))
	}
	// Clear the prefilled value, then submit empty.
	for i := 0; i < 16; i++ {
		m = press(t, m, "backspace")
	}
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd)

	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("clear-address not done-ok: %+v", topAny(m))
	}
	p, err := d.GetPeer(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("GetPeer alpha: %v", err)
	}
	if p.Address != "" {
		t.Fatalf("alpha Address = %q after empty submit, want cleared", p.Address)
	}
}

// TestMakeClientOfferedForInbound drives C → y on an inbound peer: the confirm
// explains the inbound-strip, and ops.MakeClient flips the peer to client.
func TestMakeClientOfferedForInbound(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	m := batchModel(t, dataDir, d)
	m = selectPeer(t, m, "alpha")

	m = press(t, m, "C")
	cm, ok := topAny(m).(confirmModal)
	if !ok || cm.kind != confirmMakeClient || cm.subject != "alpha" {
		t.Fatalf("C did not open make-client confirm; top=%T", topAny(m))
	}
	body := strings.Join(cm.body, "\n")
	if !strings.Contains(body, "inbound") || !strings.Contains(body, "client") {
		t.Fatalf("make-client confirm copy missing inbound->client explanation:\n%s", body)
	}
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = drain(t, nm.(Model), cmd)

	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("make-client not done-ok: %+v", topAny(m))
	}
	p, err := d.GetPeer(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("GetPeer alpha: %v", err)
	}
	if p.Inbound {
		t.Fatal("alpha still inbound after make-client")
	}
}

// TestMakeClientNotOfferedForClient checks C is a no-op (no modal) for a peer
// that already accepts no inbound.
func TestMakeClientNotOfferedForClient(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	ctx := context.Background()
	_, pubAuth, sshPub, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	// A client-style peer: inbound=false, carries a pull token.
	if err := d.InsertPeer(ctx, "laptop", 101, ssh.FingerprintSHA256(sshPub), pubAuth, "alice", false, "tok"); err != nil {
		t.Fatalf("InsertPeer laptop: %v", err)
	}
	if err := d.BumpFleetRev(ctx); err != nil {
		t.Fatalf("BumpFleetRev: %v", err)
	}
	m := batchModel(t, dataDir, d)
	m = drainReload(t, m)
	m = selectPeer(t, m, "laptop")

	m = press(t, m, "C")
	if _, ok := m.topModal(); ok {
		t.Fatalf("C opened a modal for an already-client peer; top=%T", topAny(m))
	}
}

// TestPeerActionKeysInHints asserts the new keys are advertised in the peers
// footer when mutations are enabled. The hint line is checked at a wide width so
// the assertion is not defeated by the runtime width-clamp (the footer truncates
// to the terminal width, like every other hint line).
func TestPeerActionKeysInHints(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	m := batchModel(t, dataDir, d)
	hint := strings.Join(m.footerLines(400), "\n")
	for _, want := range []string{"a address", "X remove", "C →client"} {
		if !strings.Contains(hint, want) {
			t.Fatalf("peers footer missing %q:\n%s", want, hint)
		}
	}
}
