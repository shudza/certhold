package tui

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/ops"
	"github.com/shudza/certhold/internal/sshpush"
)

// testHostKey returns a fresh ssh.PublicKey to fingerprint in the modal.
func testHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen host key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("new ssh pub: %v", err)
	}
	return sshPub
}

// confirmDial returns a dial that simulates an UNKNOWN host: it drives the
// HostKeyConfirmFn dialPush installs (accept → fakePusher, reject → error)
// exactly like the real sshpush.Dial, so the TUI's confirmHostKey bridge and
// modal are exercised end to end.
func confirmDial(key ssh.PublicKey) ops.DialFn {
	return func(_ context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		if opts.HostKeyConfirmFn == nil {
			return nil, errUnknownHostTUI
		}
		ok, err := opts.HostKeyConfirmFn(host, key)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errUnknownHostTUI
		}
		return fakePusher{}, nil
	}
}

var errUnknownHostTUI = errTUI("knownhosts: key is unknown")

type errTUI string

func (e errTUI) Error() string { return string(e) }

// confirmActionModel builds an action model whose Dial drives a host-key confirm
// for the given key, so revoke (a push-bearing action) raises the modal.
func confirmActionModel(t *testing.T, dataDir string, d *db.DB, key ssh.PublicKey) Model {
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
		BuildDeps: func(onEvent func(ops.Event), caUnlock, peerPass func() ([]byte, error), hostKeyConfirm func(host, fingerprint, keyType string) (bool, error)) ops.Deps {
			return ops.Deps{
				DB:             d,
				DataDir:        dataDir,
				CAUnlock:       caUnlock,
				PeerPass:       peerPass,
				Dial:           confirmDial(key),
				OnEvent:        onEvent,
				HostKeyConfirm: hostKeyConfirm,
			}
		},
	})
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	return nm.(Model)
}

// driveAction runs an action to completion in a single event loop (like drain)
// but answers BOTH passphrase and host-key modals from queued answers, so the
// combined passphrase-then-hostkey sequence in one action is proven not to
// deadlock or cross channels. A passphrase answer is a non-"y"/"n" string typed
// into the field; a host-key answer is "y", "n", or "esc". With no answer left
// for an open modal the loop settles. seenHostKey, if non-nil, is called with
// each host-key modal as it opens (so a test can assert on the live modal
// without splitting the action across two event loops, which would orphan the
// reader goroutines that deliver the terminal done into this loop's channel).
func driveAction(t *testing.T, m Model, cmd tea.Cmd, answers ...string) Model {
	return driveActionSeen(t, nil, m, cmd, answers...)
}

func driveActionSeen(t *testing.T, seenHostKey func(hostKeyModal), m Model, cmd tea.Cmd, answers ...string) Model {
	t.Helper()
	t.Cleanup(m.pass.close)
	msgs := make(chan tea.Msg, 64)
	hkSeen := map[string]bool{}
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

	openPrompt := func() (modal, bool) {
		top, ok := m.topModal()
		if !ok {
			return nil, false
		}
		switch top.(type) {
		case passphraseModal, hostKeyModal:
			return top, true
		}
		return nil, false
	}
	settled := func() bool {
		if _, ok := openPrompt(); ok {
			return len(answers) == 0
		}
		if pg, ok := topAny(m).(progressModal); ok && !pg.done {
			return false
		}
		return true
	}

	notice := func() {
		if seenHostKey == nil {
			return
		}
		if hm, ok := topHostKey(m); ok && !hkSeen[hm.host+hm.fingerprint] {
			hkSeen[hm.host+hm.fingerprint] = true
			seenHostKey(hm)
		}
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
			notice()
			run(c)
		case <-deadline:
			t.Fatal("driveAction timed out — possible bridge deadlock")
		case <-time.After(150 * time.Millisecond):
			prompt, ok := openPrompt()
			if ok && len(answers) > 0 {
				ans := answers[0]
				answers = answers[1:]
				switch prompt.(type) {
				case hostKeyModal:
					var km tea.KeyMsg
					if ans == "esc" {
						km = tea.KeyMsg{Type: tea.KeyEsc}
					} else {
						km = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(ans)}
					}
					nm, c := m.Update(km)
					m = nm.(Model)
					run(c)
				default:
					for _, r := range ans {
						nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
						m = nm.(Model)
					}
					nm, c := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
					m = nm.(Model)
					run(c)
				}
				continue
			}
			if settled() {
				return m
			}
		}
	}
}

func topHostKey(m Model) (hostKeyModal, bool) {
	top, ok := m.topModal()
	if !ok {
		return hostKeyModal{}, false
	}
	hm, ok := top.(hostKeyModal)
	return hm, ok
}

// TestHostKeyModalRendersFingerprint asserts the host-key modal shows the host
// and the <keyType> SHA256:… fingerprint and a yes/no affordance.
func TestHostKeyModalRendersFingerprint(t *testing.T) {
	key := testHostKey(t)
	fp := ssh.FingerprintSHA256(key)
	hm := newHostKeyModal("alpha", fp, key.Type())
	v := strings.Join(hm.view(80), "\n")
	if !strings.Contains(v, fp) {
		t.Fatalf("modal omits SHA256 fingerprint:\n%s", v)
	}
	if !strings.Contains(v, "alpha") {
		t.Fatalf("modal omits host:\n%s", v)
	}
	if !strings.Contains(v, key.Type()) {
		t.Fatalf("modal omits key type %q:\n%s", key.Type(), v)
	}
	if !strings.Contains(v, "y/enter") || !strings.Contains(v, "n/esc") {
		t.Fatalf("modal omits yes/no affordance:\n%s", v)
	}
	if hm.title() != "Verify host key" {
		t.Fatalf("unexpected title %q", hm.title())
	}
}

// TestHostKeyModalLiveFingerprint proves the fingerprint the dial computes is
// the one that reaches the modal end to end (confirmHostKey → prompt → modal).
func TestHostKeyModalLiveFingerprint(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	key := testHostKey(t)
	m := confirmActionModel(t, dataDir, d, key)

	m = press(t, m, "x")
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})

	var got hostKeyModal
	seen := false
	// Answer CA passphrase then accept the host-key modal, capturing the live
	// modal as it opens — all in one loop so the action completes cleanly.
	driveActionSeen(t, func(hm hostKeyModal) { got, seen = hm, true }, nm.(Model), cmd, pass, "y")

	if !seen {
		t.Fatal("host-key modal never opened")
	}
	if got.fingerprint != ssh.FingerprintSHA256(key) {
		t.Fatalf("live fingerprint %q != %q", got.fingerprint, ssh.FingerprintSHA256(key))
	}
	if got.host != "alpha" {
		t.Fatalf("live host %q, want alpha", got.host)
	}
}

// TestHostKeyAcceptProceeds drives revoke through CA-unlock then a yes on the
// host-key modal; the action completes (the push proceeds) with no error.
func TestHostKeyAcceptProceeds(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	key := testHostKey(t)
	m := confirmActionModel(t, dataDir, d, key)

	m = press(t, m, "x")
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = driveAction(t, nm.(Model), cmd, pass, "y")

	pg, ok := topAny(m).(progressModal)
	if !ok {
		t.Fatalf("expected progress modal, top=%T", topAny(m))
	}
	if !pg.done || pg.err != nil {
		t.Fatalf("accept did not complete cleanly: done=%v err=%v", pg.done, pg.err)
	}
	if _, err := d.GetPeer(context.Background(), "alpha"); err == nil {
		t.Fatal("alpha row should be gone after a completed revoke")
	}
}

// TestHostKeyRejectFailsCleanly drives revoke through CA-unlock then a no on the
// host-key modal; the action fails cleanly (progress shows an error, no panic,
// peer row preserved since the dial never proceeded).
func TestHostKeyRejectFailsCleanly(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	key := testHostKey(t)
	m := confirmActionModel(t, dataDir, d, key)

	m = press(t, m, "x")
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = driveAction(t, nm.(Model), cmd, pass, "n")

	pg, ok := topAny(m).(progressModal)
	if !ok {
		t.Fatalf("expected progress modal, top=%T", topAny(m))
	}
	if !pg.done {
		t.Fatal("reject left action unfinished")
	}
	if pg.err == nil {
		t.Fatal("reject should surface a dial error on the progress modal")
	}
}

// TestHostKeyRejectViaEsc proves esc rejects exactly like n (close path).
func TestHostKeyRejectViaEsc(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	key := testHostKey(t)
	m := confirmActionModel(t, dataDir, d, key)

	m = press(t, m, "x")
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = driveAction(t, nm.(Model), cmd, pass, "esc")
	pg, ok := topAny(m).(progressModal)
	if !ok || !pg.done || pg.err == nil {
		t.Fatalf("esc-reject did not fail cleanly: %T done=%v err=%v", topAny(m), pg.done, pg.err)
	}
}

// TestCombinedPassphraseThenHostKey proves both prompts fire sequentially in one
// action (revoke: CA unlock THEN dial-confirm) without deadlock or crossed
// channels: the passphrase modal is answered first, then the host-key modal, and
// the action completes cleanly.
func TestCombinedPassphraseThenHostKey(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	key := testHostKey(t)
	m := confirmActionModel(t, dataDir, d, key)

	m = press(t, m, "x")
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})

	sawHostKey := false
	// One event loop, two queued answers: the passphrase first, the host-key
	// accept second. A deadlock or crossed channel would time out driveAction.
	m = driveActionSeen(t, func(hostKeyModal) { sawHostKey = true }, nm.(Model), cmd, pass, "y")

	if !sawHostKey {
		t.Fatal("host-key modal never opened after the passphrase prompt")
	}
	pg, ok := topAny(m).(progressModal)
	if !ok || !pg.done || pg.err != nil {
		t.Fatalf("combined prompt action did not complete cleanly: %T done=%v err=%v", topAny(m), pg.done, pg.err)
	}
}

// TestStaleHostKeyPromptRejected proves a host-key prompt stamped with a
// superseded action gen is rejected (worker unblocked) without opening a modal.
func TestStaleHostKeyPromptRejected(t *testing.T) {
	m := NewModel(context.Background(), testData(), nil)
	m.actionGen = 2
	reply := make(chan hostKeyReply, 1)
	nm, _ := m.handleHostKeyPrompt(hostKeyPromptMsg{req: hostKeyReq{gen: 1, host: "h", reply: reply}})
	m = nm.(Model)
	if _, ok := m.topModal(); ok {
		t.Fatal("stale host-key prompt should open no modal")
	}
	select {
	case r := <-reply:
		if r.ok || r.err == nil {
			t.Fatalf("stale prompt should reject with error, got ok=%v err=%v", r.ok, r.err)
		}
	default:
		t.Fatal("stale prompt did not answer the worker")
	}
}
