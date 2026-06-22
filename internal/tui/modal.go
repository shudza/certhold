package tui

import (
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// modalResult tells the model what to do after a modal handled a key.
type modalResult int

const (
	// modalKeep leaves the modal open (it absorbed the key).
	modalKeep modalResult = iota
	// modalClose pops the modal without firing its action.
	modalClose
	// modalSubmit pops the modal and runs the action it carries.
	modalSubmit
)

// modal is one overlay layer. handle owns every key while the modal is on top
// of the stack; view renders the modal body the frame centers over the screen.
// Modals never run tea.Cmds themselves — they return a result and the Model's
// handleModalKey turns a modalSubmit into the right command, which keeps all
// the ops/passphrase wiring in one place.
type modal interface {
	handle(msg tea.KeyMsg) (modal, modalResult)
	view(w, h int) []string
	title() string
}

var (
	modalBorderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	modalTitleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	modalHintStyle   = lipgloss.NewStyle().Faint(true)
	pickOnStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Bold(true)
)

// confirmKind tags which action a confirmModal's yes launches.
type confirmKind int

const (
	confirmRevoke confirmKind = iota
	confirmGroupDelete
)

// confirmModal is a yes/no gate. submit carries the intent the Model turns into
// an ops command; subject names the peer/group the kind acts on.
type confirmModal struct {
	heading string
	body    []string
	kind    confirmKind
	subject string
}

func (c confirmModal) title() string { return c.heading }

func (c confirmModal) handle(msg tea.KeyMsg) (modal, modalResult) {
	switch msg.String() {
	case "y", "Y", "enter":
		return c, modalSubmit
	case "n", "N", "esc":
		return c, modalClose
	}
	return c, modalKeep
}

func (c confirmModal) view(int, int) []string {
	lines := append([]string(nil), c.body...)
	lines = append(lines, "", modalHintStyle.Render("y/enter confirm · n/esc cancel"))
	return lines
}

// passphraseModal masks input (EchoPassword) and never renders or stores the
// entered bytes anywhere but the textinput it forwards on submit. errMsg holds
// the previous attempt's ops error so a wrong passphrase can be retried in place.
type passphraseModal struct {
	heading string
	input   textinput.Model
	errMsg  string
	// reply answers the ops goroutine that raised this prompt; nil for a
	// retry placeholder that is re-armed by re-launching the action.
	reply chan passReply
}

func newPassphraseModal(heading, prompt string) passphraseModal {
	ti := textinput.New()
	ti.Prompt = prompt
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '•'
	ti.CharLimit = 256
	ti.Focus()
	return passphraseModal{heading: heading, input: ti}
}

func (p passphraseModal) title() string { return p.heading }

func (p passphraseModal) handle(msg tea.KeyMsg) (modal, modalResult) {
	switch msg.String() {
	case "enter":
		return p, modalSubmit
	case "esc":
		return p, modalClose
	}
	var cmd tea.Cmd
	p.input, cmd = p.input.Update(msg)
	_ = cmd
	return p, modalKeep
}

func (p passphraseModal) view(int, int) []string {
	lines := []string{p.input.View()}
	if p.errMsg != "" {
		lines = append(lines, "", errStyle.Render("✗ "+p.errMsg))
	}
	lines = append(lines, "", modalHintStyle.Render("enter submit · esc cancel"))
	return lines
}

// hostKeyModal is the SSH-style unknown-host-key verification gate. It shows the
// host and its <keyType> SHA256:… fingerprint and collects a yes/no. submit
// (y/enter) accepts and learns the key; close (n/esc) rejects — a plain reject,
// not a whole-action retry like the passphrase wrong-answer path. reply answers
// the ops dial goroutine that raised this prompt.
type hostKeyModal struct {
	host        string
	fingerprint string
	keyType     string
	reply       chan hostKeyReply
}

func newHostKeyModal(host, fingerprint, keyType string) hostKeyModal {
	return hostKeyModal{host: host, fingerprint: fingerprint, keyType: keyType}
}

func (h hostKeyModal) title() string { return "Verify host key" }

func (h hostKeyModal) handle(msg tea.KeyMsg) (modal, modalResult) {
	switch msg.String() {
	case "y", "Y", "enter":
		return h, modalSubmit
	case "n", "N", "esc":
		return h, modalClose
	}
	return h, modalKeep
}

func (h hostKeyModal) view(int, int) []string {
	keyType := h.keyType
	if keyType == "" {
		keyType = "key"
	}
	return []string{
		"The authenticity of host " + h.host + " can't be established.",
		keyType + " " + h.fingerprint,
		"",
		modalHintStyle.Render("y/enter accept · n/esc reject"),
	}
}

// pickKind tags which action a pickModal's submit launches, so the one generic
// multi-select serves all three pickers (peer→groups, group→members,
// peer→allowed-inbound) without forking the modal.
type pickKind int

const (
	pickPeerGroups pickKind = iota
	pickGroupMembers
	pickPeerAllowed
)

// pickModal is a multi-select list. options are sorted names; checked tracks
// membership; preChecked is the snapshot at open time so submitModal can diff
// the selection against it. submit hands back the selected set as the Model's
// action.
type pickModal struct {
	heading    string
	subject    string
	kind       pickKind
	options    []string
	checked    map[string]bool
	prechecked map[string]bool
	cursor     int
}

func newPickModal(heading, subject string, options, preChecked []string) pickModal {
	return newPickModalKind(pickPeerGroups, heading, subject, options, preChecked)
}

func newPickModalKind(kind pickKind, heading, subject string, options, preChecked []string) pickModal {
	opts := append([]string(nil), options...)
	sort.Strings(opts)
	checked := make(map[string]bool, len(preChecked))
	pre := make(map[string]bool, len(preChecked))
	for _, g := range preChecked {
		checked[g] = true
		pre[g] = true
	}
	return pickModal{heading: heading, subject: subject, kind: kind, options: opts, checked: checked, prechecked: pre}
}

func (p pickModal) handle(msg tea.KeyMsg) (modal, modalResult) {
	switch msg.String() {
	case "esc":
		return p, modalClose
	case "enter":
		return p, modalSubmit
	case "j", "down":
		if len(p.options) > 0 {
			p.cursor = clamp(p.cursor+1, 0, len(p.options)-1)
		}
		return p, modalKeep
	case "k", "up":
		if len(p.options) > 0 {
			p.cursor = clamp(p.cursor-1, 0, len(p.options)-1)
		}
		return p, modalKeep
	case " ", "x":
		if len(p.options) > 0 {
			name := p.options[p.cursor]
			p.checked[name] = !p.checked[name]
		}
		return p, modalKeep
	}
	return p, modalKeep
}

func (p pickModal) selected() []string {
	var out []string
	for _, o := range p.options {
		if p.checked[o] {
			out = append(out, o)
		}
	}
	return out
}

func (p pickModal) title() string { return p.heading }

func (p pickModal) view(w, h int) []string {
	if len(p.options) == 0 {
		return []string{
			modalHintStyle.Render("no groups exist — create one with 'certhold group create'"),
			"",
			modalHintStyle.Render("enter apply · esc cancel"),
		}
	}
	hint := modalHintStyle.Render("j/k move · space toggle · enter apply · esc cancel")

	// The body budget h already excludes the box's top/bottom border; reserve a
	// blank + the hint line for the option rows. The cue (when overflowing) takes
	// one more row, mirroring peersTableLines' visible-shrink.
	visible := h - 2
	if visible < 1 {
		visible = 1
	}
	if len(p.options) > visible && visible > 1 {
		visible--
	}
	top := 0
	if p.cursor >= visible {
		top = p.cursor - visible + 1
	}

	lines := make([]string, 0, visible+3)
	for i := top; i < len(p.options) && i < top+visible; i++ {
		o := p.options[i]
		marker := noMarker
		if i == p.cursor {
			marker = selMarker
		}
		box := "[ ]"
		if p.checked[o] {
			box = "[x]"
		}
		row := marker + box + " " + o
		if i == p.cursor {
			row = selStyle.Render(row)
		} else if p.checked[o] {
			row = pickOnStyle.Render(row)
		}
		lines = append(lines, row)
	}
	if len(p.options) > visible {
		lines = append(lines, scrollCue(p.cursor, top, visible, len(p.options)))
	}
	lines = append(lines, "", hint)
	return lines
}

// modalFrame draws the topmost modal as a bordered box centered in the w×h body
// region, then composites it over base (the underlying view, kept for context).
// It clamps every output line to w cells and the whole box to h rows so the
// fixed-height frame invariant holds with a modal open.
func modalFrame(base []string, top modal, w, h int) []string {
	out := make([]string, h)
	copy(out, base)
	for len(out) < h {
		out = append(out, "")
	}

	bodyH := h - 2
	if bodyH < 1 {
		bodyH = 1
	}
	body := top.view(w, bodyH)
	if len(body) > bodyH {
		body = body[:bodyH]
	}
	title := modalTitleStyle.Render(top.title())

	inner := lipgloss.Width(title)
	for _, l := range body {
		if lw := lipgloss.Width(l); lw > inner {
			inner = lw
		}
	}
	maxInner := w - 4
	if maxInner < 1 {
		maxInner = 1
	}
	if inner > maxInner {
		inner = maxInner
	}

	boxLines := []string{
		modalBorderStyle.Render("┌─ ") + title + " " +
			modalBorderStyle.Render(strings.Repeat("─", clampNonNeg(inner-lipgloss.Width(title)-1))+"┐"),
	}
	for _, l := range body {
		boxLines = append(boxLines, boxRow(l, inner))
	}
	boxLines = append(boxLines, modalBorderStyle.Render("└"+strings.Repeat("─", inner+2)+"┘"))

	boxW := lipgloss.Width(boxLines[0])
	left := (w - boxW) / 2
	if left < 0 {
		left = 0
	}
	startRow := (h - len(boxLines)) / 2
	if startRow < 0 {
		startRow = 0
	}
	pad := strings.Repeat(" ", left)
	for i, bl := range boxLines {
		row := startRow + i
		if row < 0 || row >= h {
			continue
		}
		out[row] = truncLine(pad+bl, w)
	}
	return out
}

func boxRow(content string, inner int) string {
	content = truncCell(content, inner)
	gap := inner - lipgloss.Width(content)
	return modalBorderStyle.Render("│ ") + content + strings.Repeat(" ", clampNonNeg(gap)) + modalBorderStyle.Render(" │")
}

func clampNonNeg(v int) int {
	if v < 0 {
		return 0
	}
	return v
}
