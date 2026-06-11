package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

var (
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	metaStyle    = lipgloss.NewStyle().Faint(true)
	tabOnStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6")).Underline(true)
	tabOffStyle  = lipgloss.NewStyle().Faint(true)
	colHeadStyle = lipgloss.NewStyle().Bold(true).Underline(true)
	selStyle     = lipgloss.NewStyle().Reverse(true)
	revokedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Faint(true)
	expiredStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Bold(true)
	dimStyle     = lipgloss.NewStyle().Faint(true)
	errStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Bold(true)
	labelStyle   = lipgloss.NewStyle().Faint(true)
)

const (
	colGap    = "  "
	selMarker = "> "
	noMarker  = "  "
	minColW   = 6
)

func (m Model) View() string {
	w, h := m.width, m.height
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}

	header := m.headerLines(w)
	footer := m.footerLines(w)
	bodyH := h - len(header) - len(footer)
	if bodyH < 1 {
		bodyH = 1
	}

	var body []string
	switch {
	case m.detail && m.view == viewPeers:
		body = m.peerDetailLines(w, bodyH)
	case m.view == viewPeers:
		body = m.peersTableLines(w, bodyH)
	case m.view == viewStatus:
		body = m.statusLines(w, bodyH)
	default:
		body = m.groupsLines(w, bodyH)
	}
	body = fitLines(body, w, bodyH)

	lines := append(append(header, body...), footer...)
	return strings.Join(lines, "\n")
}

func (m Model) headerLines(w int) []string {
	ca := "-"
	if m.data.CAVersionKnown {
		ca = fmt.Sprintf("v%d", m.data.CAVersion)
	}
	top := titleStyle.Render("certhold") + colGap +
		metaStyle.Render(fmt.Sprintf("db %s%srev %d%sca %s", m.data.DBPath, colGap, m.data.FleetRev, colGap, ca))

	tab := func(v view, label string) string {
		if m.view == v {
			return tabOnStyle.Render("[" + label + "]")
		}
		return tabOffStyle.Render(" " + label + " ")
	}
	tabs := tab(viewPeers, fmt.Sprintf("1 peers (%d)", len(m.data.Peers))) + colGap +
		tab(viewGroups, fmt.Sprintf("2 groups (%d)", len(m.data.Groups))) + colGap +
		tab(viewStatus, "3 status")
	if m.detail && m.view == viewPeers {
		tabs += colGap + tabOnStyle.Render("[peer detail]")
	}

	return []string{truncLine(top, w), truncLine(tabs, w), ""}
}

func (m Model) footerLines(w int) []string {
	n, total := len(m.filteredPeers()), len(m.data.Peers)
	if m.view == viewGroups {
		n, total = len(m.filteredGroups()), len(m.data.Groups)
	}

	var parts []string
	if m.filtering {
		parts = append(parts, m.filter.View()+metaStyle.Render(fmt.Sprintf("%s%d/%d match", colGap, n, total)))
	} else if applied := m.filters[m.view]; applied != "" {
		parts = append(parts, metaStyle.Render(fmt.Sprintf("filter %q — %d/%d shown (esc clears)", applied, n, total)))
	}
	if m.loadErr != nil {
		parts = append([]string{errStyle.Render("error: " + m.loadErr.Error())}, parts...)
	}
	status := strings.Join(parts, colGap)

	var hints string
	switch {
	case m.filtering:
		hints = "enter apply · esc clear · ctrl+c quit"
	case m.detail:
		hints = "esc back · tab/1/2/3 views · / filter · r reload · q quit"
	case m.view == viewStatus:
		hints = "tab/1/2/3 views · r refresh · q quit"
	case m.view == viewGroups:
		hints = "tab/1/2/3 views · j/k move · / filter · r reload · q quit"
	default:
		hints = "tab/1/2/3 views · j/k move · enter detail · / filter · r reload · q quit"
	}
	return []string{truncLine(status, w), truncLine(dimStyle.Render(hints), w)}
}

func (m Model) peersTableLines(w, bodyH int) []string {
	peers := m.filteredPeers()
	if len(peers) == 0 {
		if m.filters[viewPeers] != "" {
			return []string{dimStyle.Render("no peers match the filter")}
		}
		return []string{dimStyle.Render("no peers enrolled — see 'certhold enroll'")}
	}

	headers := []string{"NAME", "ADDRESS", "USER", "GROUPS", "ALLOWED", "INBOUND", "REVOKED", "SERIAL", "EXPIRES"}
	rows := make([][]string, len(peers))
	for i, p := range peers {
		rows[i] = []string{
			p.Name,
			p.DialHost,
			orDash(p.TargetUser),
			joinOrDash(p.Groups),
			joinOrDash(p.Allowed),
			yn(p.Inbound),
			yn(p.Revoked),
			fmt.Sprintf("%d", p.Serial),
			p.Expires.short(),
		}
	}
	tableW := w - len(selMarker)
	flexible := []int{0, 1, 2, 3, 4}
	dropOrder := []int{5, 7, 4, 3, 2, 1}
	keep := dropColumns(headers, rows, flexible, dropOrder, tableW)
	headers = project(headers, keep)
	for i := range rows {
		rows[i] = project(rows[i], keep)
	}
	widths := fitColumns(headers, rows, remap(flexible, keep), tableW)

	sel := clamp(m.peerIdx, 0, len(peers)-1)
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
		p := peers[i]
		marker := noMarker
		if i == sel {
			marker = selMarker
		}
		var line string
		switch {
		case i == sel:
			line = renderRow(marker, rows[i], widths, w, selStyle)
		case p.Revoked:
			line = renderRow(marker, rows[i], widths, w, revokedStyle)
		case p.Expires.expired():
			cells := padCells(rows[i], widths)
			cells[len(cells)-1] = expiredStyle.Render(cells[len(cells)-1])
			line = truncLine(marker+strings.Join(cells, colGap), w)
		default:
			line = renderRow(marker, rows[i], widths, w, lipgloss.NewStyle())
		}
		lines = append(lines, line)
	}
	if len(peers) > visible {
		lines = append(lines, scrollCue(sel, top, visible, len(peers)))
	}
	return lines
}

func (m Model) groupsLines(w, bodyH int) []string {
	groups := m.filteredGroups()
	if len(groups) == 0 {
		if m.filters[viewGroups] != "" {
			return []string{dimStyle.Render("no groups match the filter")}
		}
		return []string{dimStyle.Render("no groups — see 'certhold group create'")}
	}

	headers := []string{"NAME", "PEERS"}
	rows := make([][]string, len(groups))
	for i, g := range groups {
		rows[i] = []string{g.Name, fmt.Sprintf("%d", g.PeerCount)}
	}
	widths := fitColumns(headers, rows, []int{0}, w-len(selMarker))

	const paneH = 4
	sel := clamp(m.groupIdx, 0, len(groups)-1)
	visible := bodyH - 1 - paneH
	if len(groups) > visible && visible > 2 {
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
	for i := top; i < len(groups) && i < top+visible; i++ {
		marker, style := noMarker, lipgloss.NewStyle()
		if i == sel {
			marker, style = selMarker, selStyle
		}
		lines = append(lines, renderRow(marker, rows[i], widths, w, style))
	}
	if len(groups) > visible {
		lines = append(lines, scrollCue(sel, top, visible, len(groups)))
	}
	for len(lines) < bodyH-paneH {
		lines = append(lines, "")
	}

	g, _ := m.selectedGroup()
	rule := "── group: " + g.Name + " "
	if pad := w - lipgloss.Width(rule); pad > 0 {
		rule += strings.Repeat("─", pad)
	}
	lines = append(lines,
		truncLine(dimStyle.Render(rule), w),
		truncLine(labelStyle.Render(fmt.Sprintf("members (%d):", len(g.Members)))+" "+joinOrDash(g.Members), w),
		truncLine(labelStyle.Render(fmt.Sprintf("allowed inbound by (%d):", len(g.AllowedBy)))+" "+joinOrDash(g.AllowedBy), w),
		"",
	)
	return lines
}

func (m Model) peerDetailLines(w, bodyH int) []string {
	p, ok := m.detailPeer()
	if !ok {
		return []string{dimStyle.Render("peer no longer present — esc to go back")}
	}

	status := "active"
	if p.Revoked {
		status = errStyle.Render("REVOKED")
	}
	token := "none"
	if p.HasPullToken {
		token = "present (value never shown)"
	}
	field := func(label, value string) string {
		return truncLine(labelStyle.Render(fmt.Sprintf("%-13s", label))+value, w)
	}
	lines := []string{
		truncLine(titleStyle.Render("peer: "+p.Name), w),
		"",
		field("status", status),
		field("cert", p.Expires.window()),
		field("address", p.DialHost),
		field("user", orDash(p.TargetUser)),
		field("serial", fmt.Sprintf("%d", p.Serial)),
		field("fingerprint", p.Fingerprint),
		field("created", p.CreatedAt.UTC().Format("2006-01-02 15:04 MST")),
		field("groups", joinOrDash(p.Groups)),
		field("allowed in", joinOrDash(p.Allowed)),
		field("inbound", yn(p.Inbound)),
		field("pull token", token),
	}
	if len(lines) > bodyH && bodyH >= 2 {
		hidden := len(lines) - (bodyH - 1)
		lines = append(lines[:bodyH-1:bodyH-1],
			dimStyle.Render(fmt.Sprintf("… %d more — enlarge the terminal", hidden)))
	}
	return lines
}

func scrollCue(sel, top, visible, total int) string {
	cue := fmt.Sprintf("%d/%d", sel+1, total)
	if top > 0 {
		cue = "▲ " + cue
	}
	if top+visible < total {
		cue += " ▼"
	}
	return dimStyle.Render(cue)
}

func (c certExpiry) short() string {
	switch c.state {
	case certForever:
		return "∞"
	case certAt:
		return c.until.Format("2006-01-02")
	default:
		return "-"
	}
}

func (c certExpiry) window() string {
	switch c.state {
	case certNone:
		return "no certificate on record"
	case certForever:
		if c.from.IsZero() {
			return "valid forever"
		}
		return fmt.Sprintf("valid %s → forever", c.from.Format("2006-01-02 15:04"))
	}
	window := "valid until " + c.until.Format("2006-01-02 15:04 MST")
	if !c.from.IsZero() {
		window = fmt.Sprintf("valid %s → %s", c.from.Format("2006-01-02 15:04"), c.until.Format("2006-01-02 15:04 MST"))
	}
	if c.expired() {
		return window + " — " + expiredStyle.Render("EXPIRED "+humanDur(time.Since(c.until))+" ago")
	}
	return fmt.Sprintf("%s (expires in %s)", window, humanDur(time.Until(c.until)))
}

func humanDur(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
}

func yn(b bool) string {
	if b {
		return "Y"
	}
	return "N"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func joinOrDash(s []string) string {
	if len(s) == 0 {
		return "-"
	}
	sorted := append([]string(nil), s...)
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}

func naturalWidths(headers []string, rows [][]string) []int {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = lipgloss.Width(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if cw := lipgloss.Width(cell); cw > widths[i] {
				widths[i] = cw
			}
		}
	}
	return widths
}

// dropColumns picks which columns survive a narrow terminal: when even
// shrinking every flexible column to its floor cannot fit the table, whole
// low-priority columns are dropped (in dropOrder) so the high-priority ones
// (REVOKED, EXPIRES) stay readable instead of being amputated by the line
// clamp.
func dropColumns(headers []string, rows [][]string, flexible, dropOrder []int, w int) []int {
	nat := naturalWidths(headers, rows)
	flex := make(map[int]bool, len(flexible))
	for _, i := range flexible {
		flex[i] = true
	}
	dropped := make(map[int]bool)
	minTotal := func() int {
		t, n := 0, 0
		for i, nw := range nat {
			if dropped[i] {
				continue
			}
			if flex[i] && nw > minColW {
				nw = minColW
			}
			t += nw
			n++
		}
		return t + (n-1)*len(colGap)
	}
	for _, d := range dropOrder {
		if minTotal() <= w {
			break
		}
		dropped[d] = true
	}
	keep := make([]int, 0, len(headers))
	for i := range headers {
		if !dropped[i] {
			keep = append(keep, i)
		}
	}
	return keep
}

func project(row []string, keep []int) []string {
	out := make([]string, len(keep))
	for i, k := range keep {
		out[i] = row[k]
	}
	return out
}

func remap(idx, keep []int) []int {
	pos := make(map[int]int, len(keep))
	for i, k := range keep {
		pos[k] = i
	}
	out := make([]int, 0, len(idx))
	for _, i := range idx {
		if p, ok := pos[i]; ok {
			out = append(out, p)
		}
	}
	return out
}

// fitColumns sizes each column to its widest cell, then shrinks the listed
// flexible columns (widest first, floor minColW) until the table fits the
// terminal.
func fitColumns(headers []string, rows [][]string, flexible []int, w int) []int {
	widths := naturalWidths(headers, rows)
	total := func() int {
		t := (len(widths) - 1) * len(colGap)
		for _, cw := range widths {
			t += cw
		}
		return t
	}
	for total() > w {
		widest := -1
		for _, i := range flexible {
			if widths[i] > minColW && (widest == -1 || widths[i] > widths[widest]) {
				widest = i
			}
		}
		if widest == -1 {
			break
		}
		widths[widest]--
	}
	return widths
}

func padCells(cells []string, widths []int) []string {
	out := make([]string, len(cells))
	for i, c := range cells {
		c = truncCell(c, widths[i])
		out[i] = c + strings.Repeat(" ", widths[i]-lipgloss.Width(c))
	}
	return out
}

func renderRow(marker string, cells []string, widths []int, w int, style lipgloss.Style) string {
	line := marker + strings.Join(padCells(cells, widths), colGap)
	if lipgloss.Width(line) > w {
		line = truncCell(line, w)
	}
	return style.Render(line)
}

// truncCell clamps a possibly styled string to w terminal cells without
// splitting escape sequences (the "…" tail counts against w).
func truncCell(s string, w int) string {
	if lipgloss.Width(s) <= w {
		return s
	}
	return ansi.Truncate(s, w, "…")
}

func truncLine(s string, w int) string {
	return truncCell(s, w)
}

func fitLines(lines []string, w, h int) []string {
	out := make([]string, 0, h)
	for _, l := range lines {
		if len(out) == h {
			break
		}
		out = append(out, truncLine(l, w))
	}
	for len(out) < h {
		out = append(out, "")
	}
	return out
}
