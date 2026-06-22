package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/shudza/certhold/internal/ops"
)

// enrollResultModal shows a completed mint: the onboarding one-liner rendered
// FULL-WIDTH and wrapped (never truncated), plus the peer name and a client
// notice. The one-liner carries an ENROLL token — that is intended to be shown
// to the operator and is NOT a peer's stored pull_token (which is never
// rendered anywhere). esc dismisses.
type enrollResultModal struct {
	peer     string
	oneLiner string
	client   bool
}

func newEnrollResultModal(res ops.EnrollResult, client bool) enrollResultModal {
	return enrollResultModal{peer: res.PeerName, oneLiner: res.OneLiner, client: client}
}

func (e enrollResultModal) title() string { return "enrolled " + e.peer }

func (e enrollResultModal) handle(msg tea.KeyMsg) (modal, modalResult) {
	if msg.String() == "esc" || msg.String() == "enter" {
		return e, modalClose
	}
	return e, modalKeep
}

func (e enrollResultModal) view(w, _ int) []string {
	// The modal frame draws a 2-cell border + 1-cell padding each side, so the
	// inner content width is w-4 at most. Wrap the one-liner to that so it stays
	// visible and legible at narrow widths (e.g. 60 cols) rather than truncated.
	inner := w - 4
	if inner < 8 {
		inner = 8
	}
	lines := []string{
		okStyle.Render("✓ minted enrollment for " + e.peer),
		"",
		labelStyle.Render("run this on the new peer:"),
	}
	lines = append(lines, wrapPlain(e.oneLiner, inner)...)
	if e.client {
		lines = append(lines, "", dimStyle.Render("client-style peer; manager cannot push to it; updates arrive via 'certhold-cli refresh'."))
	}
	lines = append(lines, "", modalHintStyle.Render("esc dismiss"))
	return lines
}

// wrapPlain hard-wraps s to width cells, breaking only on cell width so the
// one-liner is never cut — every character remains on screen across the wrapped
// rows. lipgloss.Width is the cell-accurate measure (the one-liner is ASCII, so
// a byte-wise split is exact, but width-measuring keeps it correct if a URL
// ever carries wide runes).
func wrapPlain(s string, width int) []string {
	if width < 1 {
		width = 1
	}
	var out []string
	runes := []rune(s)
	for len(runes) > 0 {
		n := 0
		w := 0
		for n < len(runes) {
			cw := lipgloss.Width(string(runes[n]))
			if w+cw > width {
				break
			}
			w += cw
			n++
		}
		if n == 0 {
			n = 1
		}
		out = append(out, string(runes[:n]))
		runes = runes[n:]
	}
	if len(out) == 0 {
		out = append(out, "")
	}
	return out
}
