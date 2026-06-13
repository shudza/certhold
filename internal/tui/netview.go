package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	probeInterval    = 5 * time.Second
	probeConcurrency = 8
)

type probeResult struct {
	up      bool
	latency time.Duration
	lastOK  time.Time
}

type probeResultMsg struct {
	gen     int
	name    string
	latency time.Duration
	err     error
	at      time.Time
}

type probeTickMsg struct {
	gen int
}

func defaultTick(gen int) tea.Cmd {
	return tea.Tick(probeInterval, func(time.Time) tea.Msg { return probeTickMsg{gen: gen} })
}

func (m *Model) enterNetCmd() tea.Cmd {
	if m.probePaused {
		return nil
	}
	return m.startSweep()
}

// startSweep opens a new probe generation: results and the follow-up tick
// carry the generation, so anything from a superseded sweep — or a tick chain
// abandoned by pause/view switch — is discarded on arrival.
func (m *Model) startSweep() tea.Cmd {
	m.probeGen++
	return tea.Batch(m.sweepCmd(), m.tick(m.probeGen))
}

func (m Model) sweepCmd() tea.Cmd {
	ctx, gen, probe, now := m.ctx, m.probeGen, m.probe, m.now
	sem := make(chan struct{}, probeConcurrency)
	var cmds []tea.Cmd
	for _, p := range m.data.Peers {
		if !p.Inbound {
			continue
		}
		name, host := p.Name, p.DialHost
		cmds = append(cmds, func() tea.Msg {
			sem <- struct{}{}
			defer func() { <-sem }()
			latency, err := probe(ctx, host)
			return probeResultMsg{gen: gen, name: name, latency: latency, err: err, at: now()}
		})
	}
	return tea.Batch(cmds...)
}

func (m *Model) applyProbeResult(msg probeResultMsg) {
	if msg.gen != m.probeGen {
		return
	}
	st := m.probes[msg.name]
	st.up = msg.err == nil
	st.latency = msg.latency
	if st.up {
		st.lastOK = msg.at
	}
	m.probes[msg.name] = st
}

func (m Model) netLines(w, bodyH int) []string {
	peers := m.data.Peers
	if len(peers) == 0 {
		return []string{dimStyle.Render("no peers enrolled — see 'certhold enroll'")}
	}

	now := m.now()
	headers := []string{"PEER", "HOST", "STATUS", "LATENCY", "LAST OK"}
	rows := make([][]string, len(peers))
	styles := make([]lipgloss.Style, len(peers))
	for i, p := range peers {
		status, latency, lastOK, style := "–", "-", "-", dimStyle
		if p.Inbound {
			if st, ok := m.probes[p.Name]; ok {
				if st.up {
					status, latency, style = "● up", fmtLatency(st.latency), okStyle
				} else {
					status, style = "○ down", errStyle
				}
				if !st.lastOK.IsZero() {
					lastOK = fmtLastOK(st.lastOK, now)
				}
			}
		}
		rows[i] = []string{p.Name, p.DialHost, status, latency, lastOK}
		styles[i] = style
	}
	// Seed LAST OK at the hh:mm:ss width (8) so the column does not grow when the
	// first timestamp lands and shift HOST mid-sweep; fitColumns only widens.
	natLastOK := []int{0, 0, 0, 0, len("00:00:00")}
	widths := fitColumnsSeed(headers, rows, []int{0, 1}, w, natLastOK)

	sel := clamp(m.netIdx, 0, len(peers)-1)
	visible := bodyH - 1
	if len(peers) > visible && visible > 2 {
		visible--
	}
	if visible < 1 {
		visible = 1
	}
	top := 0
	if sel >= visible {
		top = sel - visible + 1
	}

	lines := []string{renderRow(noMarker, headers, widths, w, colHeadStyle)}
	for i := top; i < len(peers) && i < top+visible; i++ {
		marker := noMarker
		if i == sel {
			marker = selMarker
		}
		cells := padCells(rows[i], widths)
		if i == sel {
			lines = append(lines, selStyle.Render(truncCell(marker+strings.Join(cells, colGap), w)))
			continue
		}
		cells[2] = styles[i].Render(cells[2])
		lines = append(lines, truncLine(marker+strings.Join(cells, colGap), w))
	}
	if len(peers) > visible {
		lines = append(lines, scrollCue(sel, top, visible, len(peers)))
	}
	return lines
}

// fmtLastOK renders a successful-probe timestamp. Same calendar day shows the
// plain hh:mm:ss; a different day prefixes mm-dd so a timestamp older than the
// current time-of-day is not mistaken for today (the time-of-day alone is
// ambiguous past 24h).
func fmtLastOK(at, now time.Time) string {
	at, now = at.Local(), now.Local()
	clock := at.Format("15:04:05")
	if at.YearDay() == now.YearDay() && at.Year() == now.Year() {
		return clock
	}
	return at.Format("01-02") + " " + clock
}

func fmtLatency(d time.Duration) string {
	if ms := d.Milliseconds(); ms > 9999 {
		return fmt.Sprintf("%.1fs", d.Seconds())
	} else if ms > 0 {
		return fmt.Sprintf("%dms", ms)
	}
	return "<1ms"
}
