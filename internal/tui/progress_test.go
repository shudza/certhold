package tui

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/shudza/certhold/internal/ops"
)

// longProgress is a batch-action transcript with one done-line per peer
// (peer00 … peerNN), the shape a 30-peer revoke produces.
func longProgress(n int) progressModal {
	pg := newProgressModal(fmt.Sprintf("revoke %d marked", n))
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("peer%02d", i)
		pg = pg.appendEvent(ops.Event{Type: ops.EventPeerDone, Peer: name, Msg: "revoked " + name})
	}
	return pg
}

func joinView(p progressModal, bodyH int) string {
	return strings.Join(p.view(80, bodyH), "\n")
}

// TestProgressTranscriptFollowsTail: with more lines than the body height the
// window pins to the newest lines while running, the status line stays
// visible, and new events keep following the tail.
func TestProgressTranscriptFollowsTail(t *testing.T) {
	pg := longProgress(30)
	const bodyH = 10

	v := joinView(pg, bodyH)
	if !strings.Contains(v, "peer29") {
		t.Fatalf("running transcript must follow the tail (last peer missing):\n%s", v)
	}
	if strings.Contains(v, "peer00") {
		t.Fatalf("head of an overflowing transcript should be scrolled out:\n%s", v)
	}
	if !strings.Contains(v, "running… please wait") {
		t.Fatalf("status line must stay visible under the scrolled window:\n%s", v)
	}
	if got := len(pg.view(80, bodyH)); got > bodyH {
		t.Fatalf("view returned %d lines for a %d-row budget", got, bodyH)
	}

	pg = pg.appendEvent(ops.Event{Type: ops.EventPeerDone, Peer: "peer30", Msg: "revoked peer30"})
	if v := joinView(pg, bodyH); !strings.Contains(v, "peer30") {
		t.Fatalf("a new event while following must appear immediately:\n%s", v)
	}
}

// TestProgressDoneKeepsStatusAndHintVisible: after completion the tail-follow
// default shows the last lines plus the failed/done and esc-hint trailer.
func TestProgressDoneKeepsStatusAndHintVisible(t *testing.T) {
	const bodyH = 10
	pg := longProgress(30)
	pg.done = true
	pg.err = errors.New("3 peers failed")
	v := joinView(pg, bodyH)
	for _, want := range []string{"peer29", "failed: 3 peers failed", "esc dismiss"} {
		if !strings.Contains(v, want) {
			t.Errorf("done view missing %q:\n%s", want, v)
		}
	}
	if got := len(pg.view(80, bodyH)); got > bodyH {
		t.Fatalf("view returned %d lines for a %d-row budget", got, bodyH)
	}

	ok := longProgress(30)
	ok.done = true
	v = joinView(ok, bodyH)
	for _, want := range []string{"peer29", "done", "esc dismiss"} {
		if !strings.Contains(v, want) {
			t.Errorf("success view missing %q:\n%s", want, v)
		}
	}
}

// TestProgressScrollBackAndRefollow: scrolling up disengages tail-follow (new
// events no longer move the window), reveals earlier lines with no dead
// presses, and scrolling back to the bottom re-engages follow.
func TestProgressScrollBackAndRefollow(t *testing.T) {
	const bodyH = 10
	pg := longProgress(30)

	pg, isScroll := pg.scrollKey("k", bodyH)
	if !isScroll {
		t.Fatal("k must be a scroll key")
	}
	if pg.follow {
		t.Fatal("scrolling up must disengage tail-follow")
	}
	v := joinView(pg, bodyH)
	if strings.Contains(v, "peer29") {
		t.Fatalf("one 'k' from the tail must move the window immediately:\n%s", v)
	}
	if !strings.Contains(v, "running… please wait") {
		t.Fatalf("status line must survive scrolling:\n%s", v)
	}

	pg = pg.appendEvent(ops.Event{Type: ops.EventPeerDone, Peer: "peer30", Msg: "revoked peer30"})
	if v := joinView(pg, bodyH); strings.Contains(v, "peer30") {
		t.Fatalf("new events must not yank a scrolled-back window to the tail:\n%s", v)
	}

	for i := 0; i < 10; i++ {
		pg, _ = pg.scrollKey("pgup", bodyH)
	}
	if v := joinView(pg, bodyH); !strings.Contains(v, "peer00") {
		t.Fatalf("pgup to the top must reveal the first lines:\n%s", v)
	}

	for i := 0; i < 10; i++ {
		pg, _ = pg.scrollKey("pgdown", bodyH)
	}
	if !pg.follow {
		t.Fatal("scrolling to the bottom must re-engage tail-follow")
	}
	pg = pg.appendEvent(ops.Event{Type: ops.EventPeerDone, Peer: "peer31", Msg: "revoked peer31"})
	if v := joinView(pg, bodyH); !strings.Contains(v, "peer31") {
		t.Fatalf("re-engaged follow must track new events again:\n%s", v)
	}
}

// TestProgressModalScrollKeysRouteThroughModel drives the scroll through the
// real Update path with the modal open: j/k and pgup/pgdn reach the transcript,
// the frame invariants hold on a small terminal, esc while running is
// absorbed, and esc once done dismisses.
func TestProgressModalScrollKeysRouteThroughModel(t *testing.T) {
	m := newTestModel(nil)
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 12})
	m = nm.(Model)
	pg := longProgress(30)
	m.pushModal(pg)

	bottom := m.View()
	if !strings.Contains(bottom, "peer29") || strings.Contains(bottom, "peer00") {
		t.Fatalf("open progress modal must show the transcript tail:\n%s", bottom)
	}
	if lines := strings.Split(bottom, "\n"); len(lines) != 12 {
		t.Fatalf("frame height broken with a long transcript: %d lines", len(lines))
	}
	for _, l := range strings.Split(bottom, "\n") {
		if lipgloss.Width(l) > 80 {
			t.Fatalf("line overflows the 80-col frame: %q", l)
		}
	}

	m = press(t, m, "esc")
	if _, ok := topAny(m).(progressModal); !ok {
		t.Fatal("esc while running must not dismiss the progress modal")
	}

	up := press(t, m, "k")
	if v := up.View(); v == bottom {
		t.Fatalf("'k' with the modal open did not scroll the transcript:\n%s", v)
	}
	nm, _ = up.Update(tea.KeyMsg{Type: tea.KeyPgUp})
	up = nm.(Model)
	if pgm, ok := topAny(up).(progressModal); !ok || pgm.follow {
		t.Fatal("pgup must reach the modal and disengage follow")
	}

	done := topAny(m).(progressModal)
	done.done = true
	m.replaceTop(done)
	m = press(t, m, "esc")
	if _, ok := m.topModal(); ok {
		t.Fatal("esc once done must dismiss the progress modal")
	}
}
