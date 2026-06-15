package tui

import (
	"sync"
	"testing"
)

// TestPromptErrCloseNoRace exercises the hazard from issue #129: a worker parked
// in promptErr trying to send its passReq on the request channel, while the
// session is torn down by close() on another goroutine. The atomic-pointer dance
// alone does not order the channel send against the channel close, so under -race
// this surfaces as a DATA RACE (and in the worst interleaving a send-on-closed
// panic). The fix must make promptErr's send and close()'s teardown mutually
// exclusive so neither races the other.
//
// Each iteration arms a fresh single-cap channel with no consumer, so the
// worker's send blocks (the buffer fills only if it wins); close() then races in.
// We retry many times to hit the narrow window between Load and send.
func TestPromptErrCloseNoRace(t *testing.T) {
	const iters = 2000
	for i := 0; i < iters; i++ {
		s := newPassSession()
		s.arm()

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			<-start
			// The worker tries to raise a prompt; if close() wins the worker is
			// canceled (errPassphraseCanceled) or sees a nil/closed channel. Either
			// outcome is fine — what must never happen is a race or panic.
			_, _ = s.promptErr("Unlock", "CA passphrase: ", "")
		}()

		go func() {
			defer wg.Done()
			<-start
			s.close()
		}()

		close(start)
		wg.Wait()
	}
}
