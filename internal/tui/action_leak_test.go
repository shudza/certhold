package tui

import (
	"runtime"
	"sync"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/shudza/certhold/internal/ops"
)

// runReader runs a waitReqCmd on its own goroutine (as the bubbletea runtime
// would) and signals the returned WaitGroup when the reader returns. Joining the
// group is the deterministic settle: the goroutine is provably gone, no sleeps.
func runReader(s *passSession, out chan<- tea.Msg) *sync.WaitGroup {
	cmd := s.waitReqCmd()
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		out <- cmd()
	}()
	return wg
}

// TestPassReaderRetiresOnArm is the direct regression for the BLOCKING leak:
// answerPassphrase re-arms a reader after every successful submit, so the final
// reader of each action is left blocked on its channel. This proves that the
// next action's arm() — which now closes the prior channel — wakes that orphaned
// reader (it returns nil, not a passPromptMsg) so its goroutine exits. We join
// each reader's WaitGroup, so the assertion is synchronization-based, not timed.
func TestPassReaderRetiresOnArm(t *testing.T) {
	s := newPassSession()
	results := make(chan tea.Msg, 64)

	const actions = 16
	// One reader per action is the leak shape (the final re-armed reader of the
	// previous action that no consumer ever drains). Arming the next action must
	// retire it; the last one is retired by close() at session exit.
	var prev *sync.WaitGroup
	for i := 0; i < actions; i++ {
		s.arm() // closes the prior action's channel → prior reader wakes (nil)
		if prev != nil {
			prev.Wait() // deterministic: prior reader goroutine has exited
		}
		prev = runReader(s, results)
	}
	s.close() // retires the last action's reader
	prev.Wait()
	close(results)

	for msg := range results {
		if msg != nil {
			t.Fatalf("retired reader produced a message instead of nil: %#v", msg)
		}
	}
}

// TestNoGoroutineLeakAcrossActions runs N full actions through the event loop
// (drain) and asserts NumGoroutine settles back to baseline. The settle is made
// deterministic by close()-ing the session (which wakes the last reader) and
// then joining on goroutine count returning to baseline via a bounded gosched
// spin — no fixed sleeps. Pre-fix this grew by +1 per action.
func TestNoGoroutineLeakAcrossActions(t *testing.T) {
	dataDir, d, pass := seedActionEnv(t)
	m := actionModel(t, dataDir, d)

	settleGoroutines(t) // quiesce any lazily-started runtime goroutines first
	base := runtime.NumGoroutine()

	const actions = 8
	for i := 0; i < actions; i++ {
		m = press(t, m, "u")
		nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m = drain(t, nm.(Model), cmd, pass)
		if pg, ok := topAny(m).(progressModal); !ok || !pg.done || pg.err != nil {
			t.Fatalf("action %d not done-ok: %+v", i, topAny(m))
		}
		m = press(t, m, "esc")
	}

	// Each completed action leaves one re-armed reader blocked on its (now stale)
	// channel; the next action's arm() retired the one before it, and close()
	// retires the very last. After close() the count must return to baseline.
	m.pass.close()
	m.peerPass.Close()
	settleGoroutines(t)

	if got := runtime.NumGoroutine(); got > base {
		t.Fatalf("goroutine leak across %d actions: baseline=%d after=%d (delta=%d)",
			actions, base, got, got-base)
	}
}

// settleGoroutines yields until the goroutine count stops dropping, so blocked
// readers that were just woken (by a closed channel) have actually returned.
// It asserts on a stable reading, not a timer, so it is not timing-fragile: a
// woken goroutine becomes runnable immediately and a Gosched lets it finish.
func settleGoroutines(t *testing.T) {
	t.Helper()
	prev := -1
	stable := 0
	for i := 0; i < 1000; i++ {
		runtime.GC()
		runtime.Gosched()
		n := runtime.NumGoroutine()
		if n == prev {
			if stable++; stable >= 5 {
				return
			}
		} else {
			stable = 0
			prev = n
		}
	}
}

// TestSecondPromptWithinOneActionStillWorks proves the fix did not break a
// worker prompting twice in a single action (CA then peer passphrase): the
// per-action channel stays open across both prompts, so both reach the loop and
// both replies route back to the same blocked worker.
func TestSecondPromptWithinOneAction(t *testing.T) {
	s := newPassSession()
	s.gen.Store(1)
	ch := s.arm()

	// Worker that prompts twice on the same channel, like a CA-then-peer action.
	type result struct {
		first, second []byte
		err1, err2    error
	}
	done := make(chan result, 1)
	go func() {
		p1, e1 := s.prompt("CA passphrase: ")
		p2, e2 := s.prompt("Manager peer passphrase: ")
		done <- result{first: p1, second: p2, err1: e1, err2: e2}
	}()

	// First request arrives, answer it; channel must stay open for the second.
	req1 := <-ch
	req1.reply <- passReply{pass: []byte("ca-pass")}
	req2 := <-ch
	if req2.prompt != "Manager peer passphrase: " {
		t.Fatalf("second prompt label = %q, want peer passphrase", req2.prompt)
	}
	req2.reply <- passReply{pass: []byte("peer-pass")}

	r := <-done
	if r.err1 != nil || r.err2 != nil {
		t.Fatalf("worker errored: %v / %v", r.err1, r.err2)
	}
	if string(r.first) != "ca-pass" || string(r.second) != "peer-pass" {
		t.Fatalf("replies misrouted: first=%q second=%q", r.first, r.second)
	}
	s.close()
}

// TestCancelMidPromptRoutesToFailure proves cancel-mid-prompt still delivers
// errPassphraseCanceled to the blocked worker (the cancel path the modal's
// dismissal drives via answerPassphrase{err: errPassphraseCanceled}).
func TestCancelMidPromptRoutesToFailure(t *testing.T) {
	s := newPassSession()
	ch := s.arm()

	type res struct {
		pass []byte
		err  error
	}
	done := make(chan res, 1)
	go func() {
		p, e := s.prompt("CA passphrase: ")
		done <- res{pass: p, err: e}
	}()

	req := <-ch
	req.reply <- passReply{err: errPassphraseCanceled}

	r := <-done
	if r.err != errPassphraseCanceled {
		t.Fatalf("worker err = %v, want errPassphraseCanceled", r.err)
	}
	s.close()
}

// TestSessionCloseZeroesPassphrase asserts close() drops the cached CA
// passphrase so a subsequent Get re-prompts — the exit-zeroing contract the NIT
// asked for, exercised at the passSession level.
func TestSessionCloseZeroesPassphrase(t *testing.T) {
	prompts := 0
	s := &passSession{}
	c := make(chan passReq, 1)
	s.reqs.Store(&c)
	// An unlocker whose prompt counts invocations: after close() zeroes the
	// cache, the next Get must prompt again (count bumps).
	s.unlocker = ops.NewSessionUnlocker(func() ([]byte, error) {
		prompts++
		return []byte("s3cret"), nil
	})

	if _, err := s.unlocker.Get(); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if _, err := s.unlocker.Get(); err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if prompts != 1 {
		t.Fatalf("expected cache to prompt once, got %d", prompts)
	}

	s.close() // zero + retire

	if _, err := s.unlocker.Get(); err != nil {
		t.Fatalf("post-close Get: %v", err)
	}
	if prompts != 2 {
		t.Fatalf("close() did not drop the cache: prompts=%d, want 2", prompts)
	}
}
