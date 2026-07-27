package tui

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/ops"
)

type view int

const (
	viewPeers view = iota
	viewGroups
	viewStatus
	viewNet
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

	view            view
	detail          bool
	detailName      string
	detailScroll    int
	groupPaneScroll int
	peerIdx         int
	groupIdx        int
	netIdx          int

	health    *http.Client
	serve     *healthMsg
	healthSeq int

	probe       ProbeFn
	tick        func(gen int) tea.Cmd
	now         func() time.Time
	probes      map[string]probeResult
	probeGen    int
	probePaused bool

	filtering bool
	filter    textinput.Model
	filters   [viewCount]string

	// notice is the footer flash a refused key leaves behind (a mutating key on
	// the reserved manager group's row). It opens no modal and starts no action,
	// so the next keypress clears it.
	notice string

	readOnly    bool
	action      ActionDeps
	pass        *passSession
	peerPass    *ops.SessionUnlocker
	modals      []modal
	bridge      *actionBridge
	actionGen   int
	lastRun     func(ctx context.Context, deps ops.Deps) error
	lastHeading string
	passErr     string

	// enrollResult is a shared holder the mint worker writes on success; it is a
	// pointer (allocated once) so the goroutine's write is visible to the value-
	// type Model copy that processes actionDoneMsg. enrollPending marks the
	// in-flight action as an enroll so its done handler shows the result screen.
	enrollResult  *atomic.Pointer[ops.EnrollResult]
	enrollPending bool
	enrollClient  bool

	// marks is the multi-select set keyed by peer NAME (not row index) so a mark
	// rides the peer through a filter change. batchOutcome is the per-batch holder
	// the worker writes its failed-peer set into; handleActionDone reads it to
	// clear marks on the peers that succeeded and keep failed ones marked.
	marks        map[string]bool
	batchKind    batchKind
	batchOutcome *atomic.Pointer[batchOutcome]

	width  int
	height int
}

// batchKind tags which batch a confirm/pick modal's submit should fan out over
// the marked set, so the existing confirm/pick submit paths can branch into the
// aggregated run instead of the single-peer one.
type batchKind int

const (
	batchNone batchKind = iota
	batchRevoke
	batchEditGroups
	batchMembers
	batchRemove
)

func NewModel(ctx context.Context, data fleetData, reload reloader) Model {
	ti := textinput.New()
	ti.Prompt = "/"
	ti.Placeholder = "filter"
	ti.CharLimit = 64
	pass := newPassSession()
	return Model{
		ctx:          ctx,
		reload:       reload,
		data:         data,
		view:         viewPeers,
		health:       defaultHealthClient(),
		probe:        defaultProbe,
		tick:         defaultTick,
		now:          time.Now,
		probes:       map[string]probeResult{},
		filter:       ti,
		pass:         pass,
		peerPass:     pass.peerUnlocker(),
		enrollResult: &atomic.Pointer[ops.EnrollResult]{},
	}
}

// withAction installs the mutation seam; a read-only TUI omits it. Kept
// separate from NewModel so the read-only constructor and tests share one
// initializer.
func (m Model) withAction(a ActionDeps) Model {
	m.action = a
	return m
}

// RunOptions configures Run. Action is nil for a read-only dashboard; when set,
// the TUI enables mutating keys and builds ops.Deps through it (the seam tests
// fill with fakes). ReadOnly forces v1 behavior even when Action is set.
type RunOptions struct {
	Action   *ActionDeps
	ReadOnly bool
}

func Run(ctx context.Context, d *db.DB, dbPath string, in io.Reader, out io.Writer, opts RunOptions) error {
	reload := func(ctx context.Context) (fleetData, error) {
		return load(ctx, d, dbPath)
	}
	data, err := reload(ctx)
	if err != nil {
		return err
	}
	m := NewModel(ctx, data, reload)
	if opts.Action != nil && !opts.ReadOnly {
		m = m.withAction(*opts.Action)
	} else {
		m.readOnly = true
	}
	// pass and peerPass are pointers constructed once in NewModel and shared by
	// every copy of the value-type Model, so zeroing them here zeroes the live
	// caches regardless of which Model copy the program ends with. close also
	// retires the last action's re-armed passphrase reader. Mirrors the CLI's
	// defer …Zero() contract for SessionUnlocker.
	defer m.pass.close()
	defer m.peerPass.Close()

	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithContext(ctx), tea.WithInput(in), tea.WithOutput(out))
	_, err = p.Run()
	return err
}

func (m Model) Init() tea.Cmd { return nil }

func (m Model) mutationsEnabled() bool {
	return !m.readOnly && m.action.BuildDeps != nil
}

func (m Model) topModal() (modal, bool) {
	if len(m.modals) == 0 {
		return nil, false
	}
	return m.modals[len(m.modals)-1], true
}

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
		if msg.seq != m.healthSeq {
			return m, nil
		}
		m.serve = &msg
		return m, nil
	case probeTickMsg:
		if m.view != viewNet || m.probePaused || msg.gen != m.probeGen {
			return m, nil
		}
		return m, m.startSweep()
	case probeResultMsg:
		m.applyProbeResult(msg)
		return m, nil
	case passPromptMsg:
		return m.handlePassPrompt(msg)
	case hostKeyPromptMsg:
		return m.handleHostKeyPrompt(msg)
	case actionEventMsg:
		return m.handleActionEvent(msg)
	case actionDoneMsg:
		return m.handleActionDone(msg)
	case tea.KeyMsg:
		m.notice = ""
		if _, ok := m.topModal(); ok {
			return m.handleModalKey(msg)
		}
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
		switch m.view {
		case viewStatus:
			return m, m.healthCmd()
		case viewNet:
			return m, m.enterNetCmd()
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
	case "4":
		m.view = viewNet
		m.closeDetail()
		return m, m.enterNetCmd()
	case "P":
		if m.view != viewNet {
			return m, nil
		}
		return m, m.startSweep()
	case "p":
		if m.view != viewNet {
			return m, nil
		}
		m.probePaused = !m.probePaused
		if m.probePaused {
			return m, nil
		}
		return m, m.startSweep()
	case "j", "down":
		m.move(1)
		return m, nil
	case "k", "up":
		m.move(-1)
		return m, nil
	case "J":
		m.scrollGroupPane()
		return m, nil
	case "K":
		return m.startRekey()
	case "enter":
		if m.view == viewPeers {
			if p, ok := m.selectedPeer(); ok {
				m.detail = true
				m.detailName = p.Name
				m.detailScroll = 0
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
		} else if len(m.marks) > 0 {
			m.marks = nil
		}
		return m, nil
	case " ":
		if m.view == viewPeers && !m.detail {
			m.toggleMark()
		}
		return m, nil
	case "/":
		if m.view == viewStatus || m.view == viewNet {
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
	case "ctrl+l":
		if m.mutationsEnabled() {
			m.pass.unlocker.Forget()
			m.peerPass.Forget()
		}
		return m, nil
	case "u":
		return m.startEditGroups()
	case "x":
		return m.startRevoke()
	case "X":
		return m.startRemove()
	case "a":
		return m.startEditAddress()
	case "C":
		return m.startMakeClient()
	case "i":
		return m.startEditAllowed()
	case "n":
		return m.startCreateGroup()
	case "R":
		return m.startRenameGroup()
	case "D":
		return m.startDeleteGroup()
	case "m":
		return m.startGroupMembership()
	case "e":
		return m.startEnroll()
	}
	return m, nil
}

func (m *Model) move(delta int) {
	if m.detail {
		w, _ := m.frameSize()
		maxScroll := 0
		if body, ok := m.detailBody(w); ok {
			_, maxScroll = detailViewport(len(body), m.bodyHeight())
		}
		m.detailScroll = clamp(m.detailScroll+delta, 0, maxScroll)
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
		m.groupPaneScroll = 0
		n := len(m.filteredGroups())
		if n == 0 {
			m.groupIdx = 0
			return
		}
		m.groupIdx = clamp(m.groupIdx+delta, 0, n-1)
	case viewNet:
		n := len(m.data.Peers)
		if n == 0 {
			m.netIdx = 0
			return
		}
		m.netIdx = clamp(m.netIdx+delta, 0, n-1)
	}
}

// scrollGroupPane advances the groups lower pane by one window step, wrapping
// back to the top once the last line is shown. One key keeps the compact pane
// simple; the cue shows the position. A no-op unless the groups view is up and
// its pane overflows.
func (m *Model) scrollGroupPane() {
	if m.view != viewGroups {
		return
	}
	g, ok := m.selectedGroup()
	if !ok {
		return
	}
	w := m.width
	if w <= 0 {
		w = 80
	}
	body := m.groupPaneBody(g, w)
	visible := groupPaneH - 1
	if visible < 1 {
		visible = 1
	}
	if len(body) <= groupPaneH {
		m.groupPaneScroll = 0
		return
	}
	maxTop := len(body) - visible
	if m.groupPaneScroll >= maxTop {
		m.groupPaneScroll = 0
		return
	}
	m.groupPaneScroll = clamp(m.groupPaneScroll+visible, 0, maxTop)
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
	m.detailScroll = 0
	m.groupPaneScroll = 0
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
	if nn := len(m.data.Peers); nn == 0 {
		m.netIdx = 0
	} else if m.netIdx >= nn {
		m.netIdx = nn - 1
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

func (m Model) peerByName(name string) (peerRow, bool) {
	for _, p := range m.data.Peers {
		if p.Name == name {
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
