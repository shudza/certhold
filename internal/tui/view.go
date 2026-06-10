package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
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

const colGap = "  "

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
		body = m.peerDetailLines(w)
	case m.view == viewPeers:
		body = m.peersTableLines(w, bodyH)
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

	peersTab := fmt.Sprintf("1 peers (%d)", len(m.data.Peers))
	groupsTab := fmt.Sprintf("2 groups (%d)", len(m.data.Groups))
	if m.view == viewPeers {
		peersTab = tabOnStyle.Render(peersTab)
		groupsTab = tabOffStyle.Render(groupsTab)
	} else {
		peersTab = tabOffStyle.Render(peersTab)
		groupsTab = tabOnStyle.Render(groupsTab)
	}
	tabs := peersTab + colGap + groupsTab
	if m.detail && m.view == viewPeers {
		tabs += colGap + tabOnStyle.Render("peer detail")
	}

	return []string{truncLine(top, w), truncLine(tabs, w), ""}
}

func (m Model) footerLines(w int) []string {
	var status string
	switch {
	case m.filtering:
		status = m.filter.View()
	case m.loadErr != nil:
		status = errStyle.Render("error: " + m.loadErr.Error())
	case m.filter.Value() != "":
		n, total := len(m.filteredPeers()), len(m.data.Peers)
		if m.view == viewGroups {
			n, total = len(m.filteredGroups()), len(m.data.Groups)
		}
		status = metaStyle.Render(fmt.Sprintf("filter %q — %d/%d shown (esc clears)", m.filter.Value(), n, total))
	}

	var hints string
	switch {
	case m.filtering:
		hints = "enter apply · esc clear · ctrl+c quit"
	case m.detail:
		hints = "esc back · r reload · q quit"
	default:
		hints = "tab/1/2 views · j/k move · enter detail · / filter · r reload · q quit"
	}
	return []string{truncLine(status, w), truncLine(dimStyle.Render(hints), w)}
}

func (m Model) peersTableLines(w, bodyH int) []string {
	peers := m.filteredPeers()
	if len(peers) == 0 {
		if m.filter.Value() != "" {
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
	widths := fitColumns(headers, rows, []int{0, 1, 3, 4}, w)

	sel := clamp(m.peerIdx, 0, len(peers)-1)
	visible := bodyH - 1
	if visible < 1 {
		visible = 1
	}
	top := 0
	if sel >= visible {
		top = sel - visible + 1
	}

	lines := []string{renderRow(headers, widths, w, colHeadStyle)}
	for i := top; i < len(peers) && i < top+visible; i++ {
		p := peers[i]
		var line string
		switch {
		case i == sel:
			line = renderRow(rows[i], widths, w, selStyle)
		case p.Revoked:
			line = renderRow(rows[i], widths, w, revokedStyle)
		case p.Expires.expired():
			cells := padCells(rows[i], widths)
			cells[len(cells)-1] = expiredStyle.Render(cells[len(cells)-1])
			line = strings.Join(cells, colGap)
		default:
			line = renderRow(rows[i], widths, w, lipgloss.NewStyle())
		}
		lines = append(lines, line)
	}
	return lines
}

func (m Model) groupsLines(w, bodyH int) []string {
	groups := m.filteredGroups()
	if len(groups) == 0 {
		if m.filter.Value() != "" {
			return []string{dimStyle.Render("no groups match the filter")}
		}
		return []string{dimStyle.Render("no groups — see 'certhold group create'")}
	}

	headers := []string{"NAME", "PEERS"}
	rows := make([][]string, len(groups))
	for i, g := range groups {
		rows[i] = []string{g.Name, fmt.Sprintf("%d", g.PeerCount)}
	}
	widths := fitColumns(headers, rows, []int{0}, w)

	const paneH = 4
	sel := clamp(m.groupIdx, 0, len(groups)-1)
	visible := bodyH - 1 - paneH
	if visible < 1 {
		visible = 1
	}
	top := 0
	if sel >= visible {
		top = sel - visible + 1
	}

	lines := []string{renderRow(headers, widths, w, colHeadStyle)}
	for i := top; i < len(groups) && i < top+visible; i++ {
		style := lipgloss.NewStyle()
		if i == sel {
			style = selStyle
		}
		lines = append(lines, renderRow(rows[i], widths, w, style))
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
		dimStyle.Render(rule),
		truncLine(labelStyle.Render(fmt.Sprintf("members (%d):", len(g.Members)))+" "+joinOrDash(g.Members), w),
		truncLine(labelStyle.Render(fmt.Sprintf("allowed inbound by (%d):", len(g.AllowedBy)))+" "+joinOrDash(g.AllowedBy), w),
		"",
	)
	return lines
}

func (m Model) peerDetailLines(w int) []string {
	p, ok := m.selectedPeer()
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
	return []string{
		truncLine(titleStyle.Render("peer: "+p.Name), w),
		"",
		field("status", status),
		field("address", p.DialHost),
		field("user", orDash(p.TargetUser)),
		field("serial", fmt.Sprintf("%d", p.Serial)),
		field("fingerprint", p.Fingerprint),
		field("created", p.CreatedAt.UTC().Format("2006-01-02 15:04 MST")),
		field("groups", joinOrDash(p.Groups)),
		field("allowed in", joinOrDash(p.Allowed)),
		field("inbound", yn(p.Inbound)),
		field("cert", p.Expires.window()),
		field("pull token", token),
	}
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

// fitColumns sizes each column to its widest cell, then shrinks the listed
// flexible columns (widest first, floor 6) until the table fits the terminal.
func fitColumns(headers []string, rows [][]string, flexible []int, w int) []int {
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
			if widths[i] > 6 && (widest == -1 || widths[i] > widths[widest]) {
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

// renderRow joins padded cells, truncates the plain text to the terminal
// width, and only then applies the row style — styled lines can never
// overflow and wrap.
func renderRow(cells []string, widths []int, w int, style lipgloss.Style) string {
	line := strings.Join(padCells(cells, widths), colGap)
	if lipgloss.Width(line) > w {
		line = truncCell(line, w)
	}
	return style.Render(line)
}

func truncCell(s string, w int) string {
	if lipgloss.Width(s) <= w {
		return s
	}
	r := []rune(s)
	for len(r) > 0 && lipgloss.Width(string(r))+1 > w {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}

// truncLine cuts a possibly styled line to the terminal width without
// splitting escape sequences, falling back to the raw line when unstyled.
func truncLine(s string, w int) string {
	if lipgloss.Width(s) <= w {
		return s
	}
	if !strings.Contains(s, "\x1b") {
		return truncCell(s, w)
	}
	return s
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
