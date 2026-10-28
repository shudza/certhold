package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/shudza/certhold/internal/ops"
	"github.com/shudza/certhold/internal/qr"
)

var qrStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("15")).Background(lipgloss.Color("0"))

const (
	qrHint        = "enlarge the terminal to show a QR code"
	qrNoColorHint = "QR code needs a colour terminal"
)

// enrollResultModal shows a completed mint: the onboarding one-liner rendered
// FULL-WIDTH and wrapped (never truncated), plus the peer name and a client
// notice. The one-liner carries an ENROLL token — that is intended to be shown
// to the operator and is NOT a peer's stored pull_token (which is never
// rendered anywhere). The one-liner's QR code sits under it whenever the whole
// code fits the frame and colours are on; otherwise a dim hint replaces it.
// esc dismisses.
type enrollResultModal struct {
	peer     string
	oneLiner string
	client   bool
	reenroll bool
	qr       []string
}

func newEnrollResultModal(res ops.EnrollResult, client bool) enrollResultModal {
	lines, _ := qr.Lines(res.OneLiner)
	return enrollResultModal{peer: res.PeerName, oneLiner: res.OneLiner, client: client, reenroll: res.Reenroll, qr: lines}
}

func (e enrollResultModal) title() string {
	if e.reenroll {
		return "re-enroll " + e.peer
	}
	return "enrolled " + e.peer
}

func (e enrollResultModal) handle(msg tea.KeyMsg) (modal, modalResult) {
	if msg.String() == "esc" || msg.String() == "enter" {
		return e, modalClose
	}
	return e, modalKeep
}

func (e enrollResultModal) view(w, h int) []string {
	// The modal frame draws a 2-cell border + 1-cell padding each side, so the
	// inner content width is w-4 at most. Wrap the one-liner to that so it stays
	// visible and legible at narrow widths (e.g. 60 cols) rather than truncated.
	inner := w - 4
	if inner < 8 {
		inner = 8
	}
	heading := "✓ minted enrollment for " + e.peer
	runLabel := "run this on the new peer:"
	if e.reenroll {
		heading = "✓ minted re-enroll for " + e.peer
		runLabel = "run this on the peer:"
	}
	lines := []string{
		okStyle.Render(heading),
		"",
		labelStyle.Render(runLabel),
	}
	lines = append(lines, wrapPlain(e.oneLiner, inner)...)
	var tail []string
	if e.reenroll {
		tail = append(tail, "", dimStyle.Render("nothing changes on the peer until this one-liner runs on it; it supersedes any earlier unredeemed one-liner for this peer."))
	}
	if e.client {
		tail = append(tail, "", dimStyle.Render("client-style peer; manager cannot push to it; updates arrive via 'certhold-cli refresh'."))
	}
	tail = append(tail, "", modalHintStyle.Render("esc dismiss"))

	if len(e.qr) > 0 {
		lines = append(lines, "")
		switch {
		case lipgloss.ColorProfile() == termenv.Ascii:
			lines = append(lines, dimStyle.Render(qrNoColorHint))
		case qrFits(e.qr, inner, h-len(lines)-len(tail)):
			for _, l := range e.qr {
				lines = append(lines, qrStyle.Render(l))
			}
		default:
			lines = append(lines, dimStyle.Render(qrHint))
		}
	}
	return append(lines, tail...)
}

func qrFits(code []string, width, height int) bool {
	return len(code) <= height && lipgloss.Width(code[0]) <= width
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
