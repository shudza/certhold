package tui

import (
	"context"
	"io"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/shudza/certhold/internal/db"
)

type view int

const (
	viewPeers view = iota
	viewGroups
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

	view     view
	detail   bool
	peerIdx  int
	groupIdx int

	filtering bool
	filter    textinput.Model

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
		m.clampSelection()
		return m, cmd
	}

	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "tab":
		m.view = 1 - m.view
		m.detail = false
		return m, nil
	case "1":
		m.view = viewPeers
		m.detail = false
		return m, nil
	case "2":
		m.view = viewGroups
		m.detail = false
		return m, nil
	case "j", "down":
		m.move(1)
		return m, nil
	case "k", "up":
		m.move(-1)
		return m, nil
	case "enter":
		if m.view == viewPeers {
			if _, ok := m.selectedPeer(); ok {
				m.detail = true
			}
		}
		return m, nil
	case "esc":
		if m.detail {
			m.detail = false
		} else if m.filter.Value() != "" {
			m.filter.SetValue("")
			m.clampSelection()
		}
		return m, nil
	case "/":
		m.filtering = true
		m.detail = false
		m.filter.Focus()
		return m, nil
	case "r":
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
	q := strings.ToLower(strings.TrimSpace(m.filter.Value()))
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
	q := strings.ToLower(strings.TrimSpace(m.filter.Value()))
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
