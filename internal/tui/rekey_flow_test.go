package tui

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// TestRekeyConfirmGate: typing anything but the literal word "rekey" keeps the
// submit inert (enter does nothing, the modal stays open and unconfirmed).
func TestRekeyConfirmGate(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	rec := &recDial{}
	m := recModel(t, dataDir, d, rec)

	m = press(t, m, "K")
	rk, ok := topAny(m).(rekeyModal)
	if !ok {
		t.Fatalf("K did not open rekey modal; top=%T", topAny(m))
	}
	if rk.confirmed() {
		t.Fatal("fresh rekey modal already confirmed")
	}

	m = typeRunes(m, "yes") // wrong word
	rk = topAny(m).(rekeyModal)
	if rk.confirmed() {
		t.Fatalf("non-rekey text confirmed: %q", rk.confirm.Value())
	}
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Fatal("enter on unconfirmed rekey launched an action")
	}
	if _, ok := topAny(nm.(Model)).(rekeyModal); !ok {
		t.Fatalf("enter on unconfirmed rekey changed the modal; top=%T", topAny(nm.(Model)))
	}
	if got := rec.dialed(); len(got) != 0 {
		t.Fatalf("inert rekey still dialed: %v", got)
	}
}

// TestRekeySuccessStreamsPeerEvents: typing rekey + enter runs ops.Rekey; the
// progress modal carries a per-peer done line for the pushed peer (beta) and
// the self peer (alpha), and the action completes ok.
func TestRekeySuccessStreamsPeerEvents(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	rec := &recDial{}
	m := recModel(t, dataDir, d, rec)

	m = press(t, m, "K")
	m = typeRunes(m, "rekey")
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd, pass)

	pg, ok := topAny(m).(progressModal)
	if !ok {
		t.Fatalf("rekey did not land on progress modal; top=%T", topAny(m))
	}
	if !pg.done || pg.err != nil {
		t.Fatalf("rekey not done-ok: done=%v err=%v lines=%v", pg.done, pg.err, pg.lines)
	}
	tr := strings.Join(pg.lines, "\n")
	if !strings.Contains(tr, "beta") || !strings.Contains(tr, "alpha") {
		t.Fatalf("rekey transcript missing per-peer lines: %q", tr)
	}
	// beta is the lone inbound non-self peer → dialed exactly once.
	if got := rec.dialed(); strings.Join(got, ",") != "beta" {
		t.Fatalf("rekey dialed = %v, want [beta]", got)
	}
}

// TestRekeyStragglerSurfaced: a push failure on beta is reported as a straggler
// (EventPeerFailed line + an EventWarn summary) while the action itself still
// completes ok (CLI semantics: partial failure is not a hard error).
func TestRekeyStragglerSurfaced(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	rec := &recDial{failHosts: map[string]bool{"beta": true}}
	m := recModel(t, dataDir, d, rec)

	m = press(t, m, "K")
	m = typeRunes(m, "rekey")
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = drain(t, nm.(Model), cmd, pass)

	pg, ok := topAny(m).(progressModal)
	if !ok || !pg.done {
		t.Fatalf("expected done progress modal, got %+v", topAny(m))
	}
	if pg.err != nil {
		t.Fatalf("straggler must not hard-fail rekey: err=%v", pg.err)
	}
	tr := strings.Join(pg.lines, "\n")
	if !strings.Contains(tr, "beta") || !strings.Contains(tr, "✗") {
		t.Fatalf("transcript missing the failed peer line: %q", tr)
	}
	if !strings.Contains(tr, "STILL TRUST THE PREVIOUS CA") {
		t.Fatalf("transcript missing the straggler warning: %q", tr)
	}
}

// TestRekeyRotatePassphraseMismatchReprompts: with rotate on, entering two
// DIFFERENT new passphrases re-prompts (the source loops). Supplying the CA
// unlock, then a mismatched pair, then a matching pair, completes the rekey.
func TestRekeyRotatePassphraseMismatchReprompts(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	rec := &recDial{}
	m := recModel(t, dataDir, d, rec)

	m = press(t, m, "K")
	m = typeRunes(m, "rekey")
	// Toggle rotate on: tab to the rotate field, space.
	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = nm.(Model)
	m = press(t, m, " ")
	rk := topAny(m).(rekeyModal)
	if !rk.rotate {
		t.Fatal("space did not toggle rotate on")
	}
	// Back to confirm field is unnecessary; submit reads both. Confirmed already.
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	// Answers in order: CA unlock (existing pass), new pass attempt #1,
	// confirm #1 (mismatch), new pass #2, confirm #2 (match).
	m = drain(t, nm.(Model), cmd, pass, "newpass1", "DIFFERENT", "newpass2", "newpass2")

	pg, ok := topAny(m).(progressModal)
	if !ok || !pg.done || pg.err != nil {
		t.Fatalf("rotate rekey not done-ok after mismatch retry: %+v", topAny(m))
	}
}

// TestRotateSourceRepromptsOnMismatch drives rotatePassphraseSource against the
// passSession channel directly (like the leak tests): a mismatched first pair
// MUST cause a third + fourth prompt (re-prompt), and only the matching pair is
// returned. This proves the mismatch re-prompt at the source level, independent
// of drain's timing.
func TestRotateSourceRepromptsOnMismatch(t *testing.T) {
	m := NewModel(context.Background(), testData(), nil)
	m.pass.gen.Store(1)
	ch := m.pass.arm()
	src := m.rotatePassphraseSource()

	done := make(chan struct {
		pass []byte
		err  error
	}, 1)
	go func() {
		p, e := src()
		done <- struct {
			pass []byte
			err  error
		}{p, e}
	}()

	// First pair: mismatch.
	r1 := <-ch
	if r1.prompt != "New CA passphrase: " {
		t.Fatalf("prompt #1 = %q, want new", r1.prompt)
	}
	r1.reply <- passReply{pass: []byte("aaa")}
	r2 := <-ch
	r2.reply <- passReply{pass: []byte("bbb")} // differs → re-prompt expected

	// Re-prompt pair: the source must ask again (this is the assertion). The
	// re-prompt carries the mismatch note.
	r3 := <-ch
	if r3.errMsg == "" || !strings.Contains(r3.errMsg, "did not match") {
		t.Fatalf("re-prompt #3 missing mismatch note: %q", r3.errMsg)
	}
	r3.reply <- passReply{pass: []byte("ccc")}
	r4 := <-ch
	r4.reply <- passReply{pass: []byte("ccc")} // matches

	res := <-done
	if res.err != nil {
		t.Fatalf("source errored: %v", res.err)
	}
	if string(res.pass) != "ccc" {
		t.Fatalf("source returned %q, want the matched pair ccc", res.pass)
	}
	m.pass.close()
}

// TestRotatePathRetiresReadersAcrossActions is the decisive db-free leak probe
// for the rotate path: an action that prompts up to 4× via the rotate source
// (new+confirm, mismatch, new+confirm) on ONE per-action channel. After each
// action a re-armed reader is left blocked (mirroring answerPassphrase →
// waitReqCmd); the next action's arm() must retire it (closed channel → nil)
// and close() retires the last. We join every reader's WaitGroup, so the
// settle is synchronization-based (no sleeps), and sample NumGoroutine to prove
// no climb. This uses the SAME arm/close/waitReqCmd mechanism the CLI/peer
// prompts use — the rotate path adds no new retirement surface.
func TestRotatePathRetiresReadersAcrossActions(t *testing.T) {
	const actions = 16
	m := NewModel(context.Background(), testData(), nil)
	s := m.pass

	settleGoroutines(t)
	base := runtime.NumGoroutine()

	var prevReader *sync.WaitGroup
	for i := 0; i < actions; i++ {
		s.gen.Store(int64(i + 1))
		ch := s.arm() // closes prior action's channel → prior reader retires
		if prevReader != nil {
			prevReader.Wait()
		}

		src := m.rotatePassphraseSource()
		workerDone := make(chan struct{})
		go func() {
			_, _ = src() // new+confirm (mismatch) + new+confirm (match)
			close(workerDone)
		}()
		for _, ans := range [][]byte{
			[]byte("np1"), []byte("DIFFER"), // mismatch → re-prompt
			[]byte("np2"), []byte("np2"), // match
		} {
			req := <-ch
			req.reply <- passReply{pass: append([]byte(nil), ans...)}
		}
		<-workerDone

		// Model the post-submit re-armed reader the next arm()/close() must retire.
		// Capture the reader-cmd NOW (binding the current channel) exactly as
		// answerPassphrase does — evaluating it lazily inside the goroutine would
		// instead bind whatever channel a later arm() installed, which is a test
		// artifact, not the production sequence.
		cmd := s.waitReqCmd()
		readerWG := &sync.WaitGroup{}
		readerWG.Add(1)
		go func() {
			defer readerWG.Done()
			_ = cmd()
		}()
		prevReader = readerWG
	}
	s.close()
	prevReader.Wait()

	settleGoroutines(t)
	if got := runtime.NumGoroutine(); got > base+2 {
		t.Fatalf("LEAK: %d rotate-path actions grew goroutines base=%d -> %d", actions, base, got)
	}
}

// TestRotateCancelMidEntryFailsCleanly: cancelling either rotate prompt delivers
// errPassphraseCanceled to the worker (so ops.Rekey fails cleanly, never hangs)
// and the source returns it without looping.
func TestRotateCancelMidEntryFailsCleanly(t *testing.T) {
	for _, at := range []struct {
		name   string
		prompt string
	}{{"new", "New CA passphrase: "}, {"confirm", "Confirm new CA passphrase: "}} {
		t.Run(at.name, func(t *testing.T) {
			m := NewModel(context.Background(), testData(), nil)
			m.pass.gen.Store(1)
			ch := m.pass.arm()
			src := m.rotatePassphraseSource()

			done := make(chan error, 1)
			go func() { _, e := src(); done <- e }()

			if at.name == "confirm" {
				r := <-ch
				r.reply <- passReply{pass: []byte("np1")}
			}
			req := <-ch
			if req.prompt != at.prompt {
				t.Fatalf("prompt = %q, want %q", req.prompt, at.prompt)
			}
			req.reply <- passReply{err: errPassphraseCanceled}

			if e := <-done; e != errPassphraseCanceled {
				t.Fatalf("cancel at %s err = %v, want errPassphraseCanceled", at.name, e)
			}
			m.pass.close()
		})
	}
}

// TestRekeyReadOnlyGated: --read-only opens no rekey modal.
func TestRekeyReadOnlyGated(t *testing.T) {
	dataDir, d, _ := seedActionEnv(t)
	m := readOnlyModel(t, dataDir, d)
	if mm := press(t, m, "K"); func() bool { _, ok := mm.topModal(); return ok }() {
		t.Fatal("read-only: K opened the rekey modal")
	}
}
