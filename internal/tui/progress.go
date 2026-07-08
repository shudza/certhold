package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/shudza/certhold/internal/ops"
)

// progressModal renders an action's ops.Events as they stream in, then a final
// summary. It is the only modal whose content is driven by tea messages rather
// than keys: it absorbs every key (so the underlying view stays inert) — j/k,
// arrows and pgup/pgdn scroll the transcript, and esc, once done, pops it. The
// status/hint trailer never scrolls, so running/failed/done stays visible on a
// transcript longer than the modal.
type progressModal struct {
	heading string
	lines   []string
	done    bool
	err     error
	// top is the transcript window's first line when follow is off. follow (on
	// from birth) pins the window to the newest lines as events stream in;
	// scrolling up disengages it, scrolling back to the bottom re-engages it.
	top    int
	follow bool
}

func newProgressModal(heading string) progressModal {
	return progressModal{heading: heading, follow: true}
}

func (p progressModal) title() string { return p.heading }

func (p progressModal) handle(msg tea.KeyMsg) (modal, modalResult) {
	if p.done && msg.String() == "esc" {
		return p, modalClose
	}
	return p, modalKeep
}

func (p progressModal) transcript() []string {
	if len(p.lines) == 0 {
		return []string{dimStyle.Render("working…")}
	}
	return p.lines
}

// tail is the always-visible trailer under the transcript window: a separator
// blank plus the status/hint lines. Kept out of the scrolled region so the
// running/failed/done state and the esc hint can never be scrolled away.
func (p progressModal) tail(scrollable bool) []string {
	hint := func(base string) string {
		if scrollable {
			base = "j/k scroll · " + base
		}
		return modalHintStyle.Render(base)
	}
	switch {
	case !p.done:
		return []string{"", hint("running… please wait")}
	case p.err != nil:
		return []string{"", errStyle.Render("failed: " + p.err.Error()), hint("esc dismiss")}
	default:
		return []string{"", okStyle.Render("done"), hint("esc dismiss")}
	}
}

func (p progressModal) tailLen() int {
	if p.done {
		return 3
	}
	return 2
}

// viewport computes the transcript window for a modal body budget of bodyH
// rows: the rows shown and the maximum window top. Shared by scrollKey (clamp)
// and view (render) so the scroll bound always equals the render maximum —
// the same no-drift rule detailViewport enforces for the peer detail pane.
func (p progressModal) viewport(bodyH int) (visible, maxTop int) {
	avail := bodyH - p.tailLen()
	if avail < 1 {
		avail = 1
	}
	n := len(p.transcript())
	if n <= avail {
		return avail, 0
	}
	visible = avail - 1 // the overflow cue takes a row
	if visible < 1 {
		visible = 1
	}
	return visible, n - visible
}

// scrollKey applies a transcript scroll key given the modal body height the
// frame renders with. The modal never learns the terminal size, so the Model
// routes these keys here (handleModalKey) with the height it knows instead of
// going through handle. Returns false for keys that do not scroll.
func (p progressModal) scrollKey(key string, bodyH int) (progressModal, bool) {
	visible, maxTop := p.viewport(bodyH)
	var delta int
	switch key {
	case "j", "down":
		delta = 1
	case "k", "up":
		delta = -1
	case "pgdown":
		delta = visible
	case "pgup":
		delta = -visible
	default:
		return p, false
	}
	top := p.top
	if p.follow {
		top = maxTop
	}
	p.top = clamp(top+delta, 0, maxTop)
	p.follow = p.top >= maxTop
	return p, true
}

func (p progressModal) view(_, h int) []string {
	lines := p.transcript()
	visible, maxTop := p.viewport(h)
	top := maxTop
	if !p.follow {
		top = clamp(p.top, 0, maxTop)
	}
	out := append([]string(nil), lines[top:min(top+visible, len(lines))]...)
	if maxTop > 0 {
		out = append(out, scrollCue(top, top, visible, len(lines)))
	}
	out = append(out, p.tail(maxTop > 0)...)
	// On a degenerately short frame (bodyH under the trailer size) prefer the
	// trailer over transcript rows: modalFrame head-clips, so trim our own head.
	if len(out) > h {
		out = out[len(out)-h:]
	}
	return out
}

// appendEvent folds one ops.Event into the rendered transcript. EventPeerStart
// is suppressed (its line is rewritten by the following done/fail) for single-
// peer actions; multi-peer actions still get a line per peer because each peer
// emits its own done/fail.
func (p progressModal) appendEvent(e ops.Event) progressModal {
	switch e.Type {
	case ops.EventPeerStart:
		p.lines = append(p.lines, dimStyle.Render("→ "+e.Peer+" …"))
	case ops.EventPeerDone:
		p.lines = appendOrReplaceStart(p.lines, e.Peer, okStyle.Render("✓ "+e.Msg))
	case ops.EventPeerFailed:
		msg := e.Peer
		if e.Err != nil {
			msg += ": " + e.Err.Error()
		}
		p.lines = appendOrReplaceStart(p.lines, e.Peer, errStyle.Render("✗ "+msg))
	case ops.EventInfo:
		p.lines = append(p.lines, dimStyle.Render(e.Msg))
	case ops.EventWarn:
		p.lines = append(p.lines, warnStyle.Render("! "+e.Msg))
	}
	return p
}

// appendOrReplaceStart rewrites the most recent "→ peer …" placeholder for the
// named peer with its terminal line, so a single-peer push shows one line, not
// a start line plus a done line.
func appendOrReplaceStart(lines []string, peer, final string) []string {
	want := dimStyle.Render("→ " + peer + " …")
	for i := len(lines) - 1; i >= 0; i-- {
		if lines[i] == want {
			lines[i] = final
			return lines
		}
	}
	return append(lines, final)
}

// --- progress bridge -------------------------------------------------------
//
// ops runs inside a tea.Cmd goroutine (runActionCmd). Its OnEvent callback —
// invoked on that goroutine — pushes each Event onto a buffered channel. A
// reader-cmd (waitEventCmd) blocks on that channel and turns the next item into
// a tea message, re-subscribing after each one (the bubbletea streaming
// pattern). When ops returns, the goroutine closes the channel after sending a
// final actionDoneMsg, so the event loop never blocks on the worker and the
// worker never blocks on the event loop.

type actionEventMsg struct {
	gen   int
	event ops.Event
}

type actionDoneMsg struct {
	gen int
	err error
}

// actionBridge is the per-action channel set. events carries ops Events; done
// carries the terminal error. Both are read by reader-cmds and produce tea
// messages tagged with gen so a stale action (superseded by a newer one or a
// reload) is discarded on arrival, mirroring the probe generation guard.
type actionBridge struct {
	gen    int
	events chan ops.Event
	done   chan error
}

func newActionBridge(gen int) *actionBridge {
	return &actionBridge{
		gen:    gen,
		events: make(chan ops.Event, 16),
		done:   make(chan error, 1),
	}
}

func (b *actionBridge) waitEventCmd() tea.Cmd {
	gen, ch := b.gen, b.events
	return func() tea.Msg {
		e, ok := <-ch
		if !ok {
			return nil
		}
		return actionEventMsg{gen: gen, event: e}
	}
}

func (b *actionBridge) waitDoneCmd() tea.Cmd {
	gen, ch := b.gen, b.done
	return func() tea.Msg {
		return actionDoneMsg{gen: gen, err: <-ch}
	}
}
