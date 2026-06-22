package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/shudza/certhold/internal/ops"
)

// progressModal renders an action's ops.Events as they stream in, then a final
// summary. It is the only modal whose content is driven by tea messages rather
// than keys: it absorbs every key (so the underlying view stays inert) but only
// esc, once done, pops it.
type progressModal struct {
	heading string
	lines   []string
	done    bool
	err     error
}

func newProgressModal(heading string) progressModal {
	return progressModal{heading: heading}
}

func (p progressModal) title() string { return p.heading }

func (p progressModal) handle(msg tea.KeyMsg) (modal, modalResult) {
	if p.done && msg.String() == "esc" {
		return p, modalClose
	}
	return p, modalKeep
}

func (p progressModal) view(int, int) []string {
	lines := append([]string(nil), p.lines...)
	if len(lines) == 0 {
		lines = append(lines, dimStyle.Render("working…"))
	}
	lines = append(lines, "")
	switch {
	case !p.done:
		lines = append(lines, modalHintStyle.Render("running… please wait"))
	case p.err != nil:
		lines = append(lines, errStyle.Render("failed: "+p.err.Error()),
			modalHintStyle.Render("esc dismiss"))
	default:
		lines = append(lines, okStyle.Render("done"), modalHintStyle.Render("esc dismiss"))
	}
	return lines
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
