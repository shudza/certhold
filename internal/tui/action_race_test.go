package tui

import (
	"testing"
	"time"
)

// TestPromptErrCloseNoRace exercises the hazard from issue #129: a worker parked
// in promptErr trying to send its passReq on the request channel, while the
// session is torn down by close() on another goroutine. The atomic-pointer dance
// alone does not order the channel send against the channel close, so under -race
// this surfaces as a DATA RACE (and in the worst interleaving a send-on-closed
// panic). The fix must make promptErr's send and close()'s teardown mutually
// exclusive so neither races the other.
//
// The same race window also hides a missed-cancellation hang: if close() cancels
// inflight before the worker has published it, but the worker then wins the send,
// the worker parks on its reply forever. So each iteration asserts the worker
// goroutine actually returns within a deadline — a parked worker fails the test
// deterministically (per iteration) instead of only hanging the suite to timeout.
//
// Each iteration arms a fresh single-cap channel with no consumer, so the worker's
// send blocks (the buffer fills only if it wins); close() then races in. We retry
// many times to hit the narrow window between the inflight publish and the send.
func TestPromptErrCloseNoRace(t *testing.T) {
	const iters = 2000
	for i := 0; i < iters; i++ {
		s := newPassSession()
		s.arm()

		start := make(chan struct{})
		workerDone := make(chan struct{})
		closeDone := make(chan struct{})

		go func() {
			<-start
			// The worker tries to raise a prompt; if close() wins the worker is
			// canceled (errPassphraseCanceled) or sees a nil/closed channel. Either
			// outcome is fine — what must never happen is a race, panic, or hang.
			_, _ = s.promptErr("Unlock", "CA passphrase: ", "")
			close(workerDone)
		}()

		go func() {
			<-start
			s.close()
			close(closeDone)
		}()

		close(start)
		<-closeDone
		select {
		case <-workerDone:
		case <-time.After(5 * time.Second):
			t.Fatalf("iter %d: worker parked in promptErr after close() — missed cancellation", i)
		}
	}
}
