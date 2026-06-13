package tui

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/ops"
	"github.com/shudza/certhold/internal/sshpush"
)

// --- fake push transport ---------------------------------------------------

type fakePusher struct{}

func (p fakePusher) WriteFileAtomic(context.Context, string, []byte, fs.FileMode) error { return nil }
func (p fakePusher) ReadFile(context.Context, string) ([]byte, error)                   { return nil, nil }
func (p fakePusher) SpliceConfigBlock(context.Context, string, string, string) error    { return nil }
func (p fakePusher) ReloadSSHD(context.Context) error                                   { return nil }
func (p fakePusher) VerifyHealth(context.Context) error                                 { return nil }
func (p fakePusher) Close() error                                                       { return nil }

func fakeDial(context.Context, string, sshpush.Options) (sshpush.Pusher, error) {
	return fakePusher{}, nil
}

// seedActionEnv builds an encrypted-CA db with an inbound root peer "alpha" (in
// groups infra/db) and a second peer "beta", plus the "ops" group, so edit-
// groups and revoke have real ops paths to drive. It returns the dataDir, the
// db, and the CA passphrase the tests must enter.
func seedActionEnv(t *testing.T) (string, *db.DB, string) {
	t.Helper()
	dataDir := t.TempDir()
	const pass = "s3cret"
	if _, err := ca.GenerateWithPassphrase(filepath.Join(dataDir, "ca"), []byte(pass)); err != nil {
		t.Fatalf("GenerateWithPassphrase: %v", err)
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
	for _, g := range []string{"infra", "db", "ops"} {
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
		if err := d.SetPeerGroups(ctx, name, []string{"infra"}); err != nil {
			t.Fatalf("SetPeerGroups %s: %v", name, err)
		}
		if err := d.SetPeerAllowedGroups(ctx, name, []string{"infra"}); err != nil {
			t.Fatalf("SetPeerAllowedGroups %s: %v", name, err)
		}
	}
	if err := d.SetPeerGroups(ctx, "alpha", []string{"infra", "db"}); err != nil {
		t.Fatalf("SetPeerGroups alpha: %v", err)
	}
	if err := d.BumpFleetRev(ctx); err != nil {
		t.Fatalf("BumpFleetRev: %v", err)
	}
	return dataDir, d, pass
}

func actionModel(t *testing.T, dataDir string, d *db.DB) Model {
	t.Helper()
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
		BuildDeps: func(onEvent func(ops.Event), caUnlock, peerPass func() ([]byte, error)) ops.Deps {
			return ops.Deps{
				DB:       d,
				DataDir:  dataDir,
				CAUnlock: caUnlock,
				PeerPass: peerPass,
				Dial:     fakeDial,
				OnEvent:  onEvent,
			}
		},
	})
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	return nm.(Model)
}

// drain runs an action to completion in a single event loop, mirroring the
// bubbletea runtime: each cmd runs on its own goroutine; a tea.BatchMsg result
// is unpacked into more cmds; every other result feeds Update and the cmd it
// returns is run too. Whenever the loop goes quiet with a passphrase modal on
// top, it dequeues the next answer and types it (or stops if answers run out,
// leaving the modal open). Keeping the whole action in one loop is what lets
// the long-lived reader cmds (waitEvent/waitDone/waitReq) deliver to the same
// msgs channel — and proves no step deadlocks the loop.
func drain(t *testing.T, m Model, cmd tea.Cmd, answers ...string) Model {
	t.Helper()
	// Retire the last action's re-armed passphrase reader at test end so a
	// parked waitReqCmd goroutine never lingers past the test. close is
	// idempotent, so multiple drains in one test register it safely.
	t.Cleanup(m.pass.close)
	msgs := make(chan tea.Msg, 64)
	var run func(c tea.Cmd)
	run = func(c tea.Cmd) {
		if c == nil {
			return
		}
		go func() {
			if msg := c(); msg != nil {
				msgs <- msg
			}
		}()
	}
	run(cmd)

	// settled reports the loop may stop: no action is mid-flight (any progress
	// modal has finished) and no queued passphrase answer is owed to an open
	// modal. Crypto-heavy actions (rekey) can idle >100ms mid-run, so a quiet
	// gap alone must not end the loop.
	settled := func() bool {
		if _, ok := topPassphrase(m); ok {
			// A passphrase modal with answers owed is not settled; with none
			// owed it is the intended terminal state (re-prompt assertions).
			return len(answers) == 0
		}
		if pg, ok := topAny(m).(progressModal); ok && !pg.done {
			return false
		}
		return true
	}

	deadline := time.After(5 * time.Second)
	for {
		select {
		case msg := <-msgs:
			if batch, ok := msg.(tea.BatchMsg); ok {
				for _, c := range batch {
					run(c)
				}
				continue
			}
			nm, c := m.Update(msg)
			m = nm.(Model)
			run(c)
		case <-deadline:
			t.Fatal("drain timed out — possible bridge deadlock")
		case <-time.After(150 * time.Millisecond):
			if _, ok := topPassphrase(m); ok && len(answers) > 0 {
				ans := answers[0]
				answers = answers[1:]
				for _, r := range ans {
					nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
					m = nm.(Model)
				}
				nm, c := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
				m = nm.(Model)
				run(c)
				continue
			}
			if settled() {
				return m
			}
		}
	}
}

func topAny(m Model) modal {
	top, _ := m.topModal()
	return top
}

func topPassphrase(m Model) (passphraseModal, bool) {
	top, ok := m.topModal()
	if !ok {
		return passphraseModal{}, false
	}
	p, ok := top.(passphraseModal)
	return p, ok
}

func peerGroups(t *testing.T, d *db.DB, name string) []string {
	t.Helper()
	g, err := d.GetPeerGroups(context.Background(), name)
	if err != nil {
		t.Fatalf("GetPeerGroups %s: %v", name, err)
	}
	return g
}

// TestRevokeFlow drives confirm → passphrase → progress and asserts the db row
// and the reloaded table both show the peer revoked.
func TestRevokeFlow(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	m := actionModel(t, dataDir, d)

	m = press(t, m, "x")
	if _, ok := topAny(m).(confirmModal); !ok {
		t.Fatalf("x did not open confirm modal; top=%T", topAny(m))
	}
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = drain(t, nm.(Model), cmd, pass)

	pg, ok := topAny(m).(progressModal)
	if !ok {
		t.Fatalf("expected progress modal after revoke, top=%T", topAny(m))
	}
	if !pg.done || pg.err != nil {
		t.Fatalf("progress not done-ok: done=%v err=%v lines=%v", pg.done, pg.err, pg.lines)
	}

	p, err := d.GetPeer(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if !p.Revoked {
		t.Fatal("db: alpha not revoked")
	}
	row, ok := m.peerByName("alpha")
	if !ok || !row.Revoked {
		t.Fatalf("reloaded table does not show alpha revoked: row=%+v ok=%v", row, ok)
	}
}

// TestEditGroupsFlow toggles a group off and applies the diff via ops, then
// asserts the peer row reflects the new membership after reload.
func TestEditGroupsFlow(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	m := actionModel(t, dataDir, d)

	m = press(t, m, "u")
	pick, ok := topAny(m).(pickModal)
	if !ok {
		t.Fatalf("u did not open pick modal; top=%T", topAny(m))
	}
	if !pick.checked["infra"] || !pick.checked["db"] {
		t.Fatalf("pick not pre-checked with current groups: %+v", pick.checked)
	}
	// cursor starts at options[0] (db, after sort); toggle db off.
	if pick.options[0] != "db" {
		t.Fatalf("expected sorted options[0]=db, got %q", pick.options[0])
	}
	m = press(t, m, " ") // uncheck db
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd, pass)

	if got := peerGroups(t, d, "alpha"); len(got) != 1 || got[0] != "infra" {
		t.Fatalf("db groups for alpha = %v, want [infra]", got)
	}
	row, _ := m.peerByName("alpha")
	if strings.Join(row.Groups, ",") != "infra" {
		t.Fatalf("reloaded row groups = %v, want [infra]", row.Groups)
	}
}

// TestPassphraseCachedAcrossActions checks the unlocker prompts once: a second
// action runs without re-prompting.
func TestPassphraseCachedAcrossActions(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	m := actionModel(t, dataDir, d)

	// First action: edit groups on alpha (no-op diff keeps it simple).
	m = press(t, m, "u")
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd, pass)
	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("first action not done-ok: %+v", topAny(m))
	}
	m = press(t, m, "esc") // dismiss progress

	// Second action: edit groups on beta — must NOT prompt again. No answer
	// is supplied to drain, so a re-prompt would leave the passphrase modal
	// open and fail the assertion below.
	m = press(t, m, "j") // move to beta
	row, _ := m.selectedPeer()
	if row.Name != "beta" {
		t.Fatalf("expected beta selected, got %q", row.Name)
	}
	m = press(t, m, "u")
	nm, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd)
	if _, ok := topPassphrase(m); ok {
		t.Fatal("second action re-prompted for passphrase; cache not used")
	}
	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("second action not done-ok: %+v (%T)", topAny(m), topAny(m))
	}
}

// TestForgetPassphraseReprompts checks ctrl+l drops the cache so the next
// action prompts again.
func TestForgetPassphraseReprompts(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	m := actionModel(t, dataDir, d)

	m = press(t, m, "u")
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd, pass)
	m = press(t, m, "esc")

	m = press(t, m, "ctrl+l") // forget

	m = press(t, m, "u")
	nm, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd) // no answer supplied; modal must reappear
	if _, ok := topPassphrase(m); !ok {
		t.Fatalf("ctrl+l did not force a re-prompt; top=%T", topAny(m))
	}
}

// TestWrongPassphraseRetry checks a wrong passphrase surfaces the ops error in
// a fresh passphrase modal and the right one then completes the action.
func TestWrongPassphraseRetry(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	m := actionModel(t, dataDir, d)

	m = press(t, m, "u")
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	// First answer is wrong (action fails → retry modal reopens carrying the
	// ops error), second is correct (action completes). Both are consumed in
	// one event loop so the relaunched worker's reader cmds stay live.
	m = drain(t, nm.(Model), cmd, "wrong", pass)

	if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
		t.Fatalf("retry with correct passphrase did not complete: %+v (%T)", topAny(m), topAny(m))
	}
}

// TestWrongPassphraseErrorShown checks the error from a failed unlock is folded
// into the reopened passphrase modal (the retry path's user-visible surface).
func TestWrongPassphraseErrorShown(t *testing.T) {
	m := NewModel(context.Background(), testData(), nil)
	m.actionGen = 1
	m.passErr = "load ca: parse encrypted private key: x509: decryption password incorrect"
	reply := make(chan passReply, 1)
	nm, _ := m.handlePassPrompt(passPromptMsg{req: passReq{gen: 1, heading: "Unlock", prompt: "CA passphrase: ", reply: reply}})
	m = nm.(Model)
	pm, ok := topPassphrase(m)
	if !ok {
		t.Fatalf("expected passphrase modal, got %T", topAny(m))
	}
	if !isPassphraseError(errors.New(pm.errMsg)) {
		t.Fatalf("retry modal errMsg not a passphrase error: %q", pm.errMsg)
	}
	v := strings.Join(pm.view(40), "\n")
	if !strings.Contains(v, "incorrect") {
		t.Fatalf("passphrase modal view omits the error: %q", v)
	}
	reply <- passReply{err: errPassphraseCanceled}
}

// TestReadOnlyBlocksMutations verifies a read-only model opens no modal on the
// mutating keys and shows the read-only footer marker.
func TestReadOnlyBlocksMutations(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	reload := func(ctx context.Context) (fleetData, error) {
		return load(ctx, d, filepath.Join(dataDir, "state.db"))
	}
	data, _ := reload(context.Background())
	m := NewModel(context.Background(), data, reload)
	m.readOnly = true
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = nm.(Model)

	for _, k := range []string{"u", "x", "ctrl+l"} {
		mm := press(t, m, k)
		if _, ok := mm.topModal(); ok {
			t.Fatalf("read-only: key %q opened a modal", k)
		}
	}
	if !strings.Contains(m.View(), "read-only") {
		t.Fatal("read-only footer marker missing")
	}
}

// modalStates returns one model per modal kind, all sized identically, for the
// invariant sweeps below. The passphrase modal carries typed input to prove the
// mask (not the value) is what renders.
func modalStates(t *testing.T, w, h int) map[string]Model {
	t.Helper()
	base := NewModel(context.Background(), testData(), nil).withAction(ActionDeps{
		BuildDeps: func(func(ops.Event), func() ([]byte, error), func() ([]byte, error)) ops.Deps {
			return ops.Deps{}
		},
	})
	nm, _ := base.Update(tea.WindowSizeMsg{Width: w, Height: h})
	base = nm.(Model)

	confirm := base
	confirm.pushModal(confirmModal{heading: "revoke alpha", body: []string{"Revoke peer alpha?"}})

	pick := base
	pick.pushModal(newPickModal("edit groups: alpha", "alpha", []string{"infra", "ops", "db"}, []string{"infra"}))

	pmModal := newPassphraseModal("Unlock", "CA passphrase: ")
	pmModal.input.SetValue("hunter2")
	passM := base
	passM.pushModal(pmModal)

	prog := base
	pg := newProgressModal("revoke alpha").appendEvent(ops.Event{Type: ops.EventPeerStart, Peer: "alpha"})
	pg = pg.appendEvent(ops.Event{Type: ops.EventPeerDone, Peer: "alpha", Msg: "rekeyed alpha (serial 7)"})
	pg.done = true
	prog.pushModal(pg)

	rekey := base
	rekey.pushModal(newRekeyModal())

	enroll := base
	enroll.pushModal(newEnrollFormModal([]string{"infra", "db", "ops"}, map[string]bool{"alpha": true}))

	result := base
	result.pushModal(newEnrollResultModal(ops.EnrollResult{
		PeerName: "edge1",
		OneLiner: "curl -kfsSL https://certhold.home.lan/enroll/zh7_ByXd9epfrwqyaA0w54t--_lUDRxUmAP8_VZb_ZE.sh | bash",
	}, false))

	return map[string]Model{
		"confirm": confirm, "pick": pick, "passphrase": passM, "progress": prog,
		"rekey": rekey, "enroll": enroll, "result": result,
	}
}

// TestModalsPreserveLayout asserts the v1 frame invariants hold with each modal
// open: exact line count == height and every line clamped to width, under a
// forced ANSI256 profile (with a vacuity guard).
func TestModalsPreserveLayout(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.ANSI256)
	defer lipgloss.SetColorProfile(prev)

	sawANSI := false
	for _, size := range []tea.WindowSizeMsg{{Width: 100, Height: 30}, {Width: 80, Height: 24}, {Width: 40, Height: 12}} {
		for name, st := range modalStates(t, size.Width, size.Height) {
			v := st.View()
			if strings.Contains(v, "\x1b[") {
				sawANSI = true
			}
			lines := strings.Split(v, "\n")
			if len(lines) != size.Height {
				t.Fatalf("%dx%d %s modal: got %d lines, want %d", size.Width, size.Height, name, len(lines), size.Height)
			}
			for _, l := range lines {
				if lw := lipgloss.Width(l); lw > size.Width {
					t.Fatalf("%dx%d %s modal: line overflows (%d > %d): %q", size.Width, size.Height, name, lw, size.Width, l)
				}
			}
		}
	}
	if !sawANSI {
		t.Fatal("forced color profile produced no ANSI — overflow checks are vacuous")
	}
}

// TestPassphraseNeverEchoed checks the entered passphrase value never appears in
// any rendered frame (the mask glyph stands in for it).
func TestPassphraseNeverEchoed(t *testing.T) {
	for _, st := range modalStates(t, 80, 24) {
		if strings.Contains(st.View(), "hunter2") {
			t.Fatalf("passphrase value leaked into a rendered view:\n%s", st.View())
		}
	}
}

// TestModalKeepsPullTokenHidden re-checks the pull_token invariant with a modal
// open over the peers/detail views.
func TestModalKeepsPullTokenHidden(t *testing.T) {
	path, _ := seedTuiDB(t)
	d, err := db.Open(path)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	fd, err := load(context.Background(), d, path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	m := NewModel(context.Background(), fd, nil).withAction(ActionDeps{
		BuildDeps: func(func(ops.Event), func() ([]byte, error), func() ([]byte, error)) ops.Deps {
			return ops.Deps{}
		},
	})
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = nm.(Model)
	m = press(t, m, "u") // open pick modal over the peers table
	if strings.Contains(m.View(), "tok-secret") {
		t.Fatalf("pull token leaked with modal open:\n%s", m.View())
	}
}
