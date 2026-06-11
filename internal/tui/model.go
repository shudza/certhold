package tui

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/shudza/certhold/internal/db"
)

type view int

const (
	viewPeers view = iota
	viewGroups
	viewStatus
	viewCount
)

// reloader abstracts the data source so tests can drive Update with a seeded
// snapshot and never need a tty or a live program loop.
type reloader func(ctx context.Context) (fleetData, error)

type reloadedMsg struct {
	data fleetData
	err  error
}

type Model struct {
	ctx     context.Context
	reload  reloader
	data    fleetData
	loadErr error

	view       view
	detail     bool
	detailName string
	peerIdx    int
	groupIdx   int

	health *http.Client
	serve  *healthMsg

	filtering bool
	filter    textinput.Model
	filters   [viewCount]string

	width  int
	height int
}

func NewModel(ctx context.Context, data fleetData, reload reloader) Model {
	ti := textinput.New()
	ti.Prompt = "/"
	ti.Placeholder = "filter"
	ti.CharLimit = 64
	return Model{
		ctx:    ctx,
		reload: reload,
		data:   data,
		view:   viewPeers,
		health: defaultHealthClient(),
		filter: ti,
	}
}

func Run(ctx context.Context, d *db.DB, dbPath string, in io.Reader, out io.Writer) error {
	reload := func(ctx context.Context) (fleetData, error) {
		return load(ctx, d, dbPath)
	}
	data, err := reload(ctx)
	if err != nil {
		return err
	}
	m := NewModel(ctx, data, reload)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithContext(ctx), tea.WithInput(in), tea.WithOutput(out))
	_, err = p.Run()
	return err
}

func (m Model) Init() tea.Cmd { return nil }

func (m Model) reloadCmd() tea.Cmd {
	return func() tea.Msg {
		data, err := m.reload(m.ctx)
		return reloadedMsg{data: data, err: err}
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case reloadedMsg:
		if msg.err != nil {
			m.loadErr = msg.err
			return m, nil
		}
		m.loadErr = nil
		m.data = msg.data
		m.clampSelection()
		return m, nil
	case healthMsg:
		m.serve = &msg
		return m, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.filtering {
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			m.filtering = false
			m.filter.SetValue("")
			m.filters[m.view] = ""
			m.filter.Blur()
			m.clampSelection()
			return m, nil
		case "enter":
			m.filtering = false
			m.filter.Blur()
			m.clampSelection()
			return m, nil
		}
		var cmd tea.Cmd
		m.filter, cmd = m.filter.Update(msg)
		m.filters[m.view] = m.filter.Value()
		m.clampSelection()
		return m, cmd
	}

	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "tab":
		m.view = (m.view + 1) % viewCount
		m.closeDetail()
		if m.view == viewStatus {
			return m, m.healthCmd()
		}
		return m, nil
	case "1":
		m.view = viewPeers
		m.closeDetail()
		return m, nil
	case "2":
		m.view = viewGroups
		m.closeDetail()
		return m, nil
	case "3":
		m.view = viewStatus
		m.closeDetail()
		return m, m.healthCmd()
	case "j", "down":
		m.move(1)
		return m, nil
	case "k", "up":
		m.move(-1)
		return m, nil
	case "enter":
		if m.view == viewPeers {
			if p, ok := m.selectedPeer(); ok {
				m.detail = true
				m.detailName = p.Name
			}
		}
		return m, nil
	case "esc":
		if m.detail {
			m.closeDetail()
		} else if m.filters[m.view] != "" {
			m.filters[m.view] = ""
			m.filter.SetValue("")
			m.clampSelection()
		}
		return m, nil
	case "/":
		if m.view == viewStatus {
			return m, nil
		}
		m.filtering = true
		m.closeDetail()
		m.filter.SetValue(m.filters[m.view])
		m.filter.CursorEnd()
		m.filter.Focus()
		return m, nil
	case "r":
		if m.view == viewStatus {
			return m, tea.Batch(m.reloadCmd(), m.healthCmd())
		}
		return m, m.reloadCmd()
	}
	return m, nil
}

func (m *Model) move(delta int) {
	if m.detail {
		return
	}
	switch m.view {
	case viewPeers:
		n := len(m.filteredPeers())
		if n == 0 {
			m.peerIdx = 0
			return
		}
		m.peerIdx = clamp(m.peerIdx+delta, 0, n-1)
	case viewGroups:
		n := len(m.filteredGroups())
		if n == 0 {
			m.groupIdx = 0
			return
		}
		m.groupIdx = clamp(m.groupIdx+delta, 0, n-1)
	}
}

// closeDetail leaves the detail pane and re-points the table selection at the
// pinned peer, which may have moved (or vanished) since the pane opened.
func (m *Model) closeDetail() {
	if m.detail && m.detailName != "" {
		for i, p := range m.filteredPeers() {
			if p.Name == m.detailName {
				m.peerIdx = i
				break
			}
		}
	}
	m.detail = false
	m.detailName = ""
}

func (m *Model) clampSelection() {
	if np := len(m.filteredPeers()); np == 0 {
		m.peerIdx = 0
	} else if m.peerIdx >= np {
		m.peerIdx = np - 1
	}
	if ng := len(m.filteredGroups()); ng == 0 {
		m.groupIdx = 0
	} else if m.groupIdx >= ng {
		m.groupIdx = ng - 1
	}
}

func (m Model) filteredPeers() []peerRow {
	q := strings.ToLower(strings.TrimSpace(m.filters[viewPeers]))
	if q == "" {
		return m.data.Peers
	}
	var out []peerRow
	for _, p := range m.data.Peers {
		hay := strings.ToLower(p.Name + " " + p.DialHost + " " + p.TargetUser + " " +
			strings.Join(p.Groups, ",") + " " + strings.Join(p.Allowed, ","))
		if fuzzyMatch(q, hay) {
			out = append(out, p)
		}
	}
	return out
}

func (m Model) filteredGroups() []groupRow {
	q := strings.ToLower(strings.TrimSpace(m.filters[viewGroups]))
	if q == "" {
		return m.data.Groups
	}
	var out []groupRow
	for _, g := range m.data.Groups {
		if fuzzyMatch(q, strings.ToLower(g.Name)) {
			out = append(out, g)
		}
	}
	return out
}

// detailPeer resolves the detail pane's peer by name, not index, so a reload
// that removes or reorders peers can never silently swap the shown record.
func (m Model) detailPeer() (peerRow, bool) {
	for _, p := range m.filteredPeers() {
		if p.Name == m.detailName {
			return p, true
		}
	}
	return peerRow{}, false
}

func (m Model) selectedPeer() (peerRow, bool) {
	ps := m.filteredPeers()
	if len(ps) == 0 {
		return peerRow{}, false
	}
	return ps[clamp(m.peerIdx, 0, len(ps)-1)], true
}

func (m Model) selectedGroup() (groupRow, bool) {
	gs := m.filteredGroups()
	if len(gs) == 0 {
		return groupRow{}, false
	}
	return gs[clamp(m.groupIdx, 0, len(gs)-1)], true
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// fuzzyMatch reports whether every rune of needle appears in haystack in
// order (subsequence match), the conventional terminal fuzzy-filter semantics.
func fuzzyMatch(needle, haystack string) bool {
	if needle == "" {
		return true
	}
	i := 0
	nr := []rune(needle)
	for _, h := range haystack {
		if h == nr[i] {
			i++
			if i == len(nr) {
				return true
			}
		}
	}
	return false
}
