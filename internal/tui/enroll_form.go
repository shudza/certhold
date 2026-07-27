package tui

import (
	"context"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/shudza/certhold/internal/ops"
)

// enroll form fields, in tab order.
const (
	efName = iota
	efGroups
	efAllowed
	efUser
	efAddress
	efClient
	efSubmit
	efCount
)

// enrollFormModal is the single self-contained mint-enrollment form. It holds a
// text input per free-text field and an inline multi-select per group field, so
// the whole form is one escapable modal (esc cancels at any step). The two
// pickers reuse the same checked/cursor mechanics as pickModal without forking
// it into a stack of modals. taken is the set of existing peer names the name
// field validates against (non-empty AND unique).
type enrollFormModal struct {
	name    textinput.Model
	user    textinput.Model
	address textinput.Model

	groupOpts []string
	groupSet  map[string]bool
	groupCur  int

	allowOpts []string
	allowSet  map[string]bool
	allowCur  int

	client bool
	field  int

	taken map[string]bool
	err   string

	// reenroll marks the detail-page re-enroll variant: fixedName is the
	// existing peer being reconfigured, the name field is locked (skipped in
	// the tab order, never validated as taken) and the submit runs the same
	// MintEnroll upsert, which stages everything until the one-liner runs.
	reenroll  bool
	fixedName string
}

func newEnrollFormModal(groups []string, taken map[string]bool) enrollFormModal {
	name := textinput.New()
	name.Prompt = ""
	name.CharLimit = 64
	name.Focus()
	user := textinput.New()
	user.Prompt = ""
	user.CharLimit = 64
	addr := textinput.New()
	addr.Prompt = ""
	addr.CharLimit = 255

	opts := append([]string(nil), groups...)
	sort.Strings(opts)
	return enrollFormModal{
		name:      name,
		user:      user,
		address:   addr,
		groupOpts: opts,
		groupSet:  map[string]bool{},
		allowOpts: append([]string(nil), opts...),
		allowSet:  map[string]bool{},
		taken:     taken,
		field:     efName,
	}
}

// newReenrollFormModal builds the detail-page re-enroll variant of the form,
// pre-filled from the peer's current configuration: groups and allowed
// pre-checked (the hidden manager principal is not offered and is preserved at
// submit), user/address pre-filled, the client toggle mirroring the row. The
// name is fixed; focus starts on the groups picker.
func newReenrollFormModal(groups []string, p peerRow) enrollFormModal {
	e := newEnrollFormModal(groups, nil)
	e.reenroll = true
	e.fixedName = p.Name
	e.name.SetValue(p.Name)
	for _, g := range p.Groups {
		e.groupSet[g] = true
	}
	for _, g := range p.Allowed {
		e.allowSet[g] = true
	}
	e.user.SetValue(p.TargetUser)
	e.address.SetValue(p.Address)
	e.client = !p.Inbound
	e.field = efGroups
	e.focusField()
	return e
}

func (e enrollFormModal) title() string {
	if e.reenroll {
		return "re-enroll " + e.fixedName
	}
	return "enroll peer"
}

// validateName returns the empty string when the trimmed name is a legal new
// peer, else the reason it is rejected (drives the inline error + submit gate).
// A re-enroll form's name is fixed to an existing peer, so it always passes.
func (e enrollFormModal) validateName() string {
	if e.reenroll {
		return ""
	}
	n := strings.TrimSpace(e.name.Value())
	if n == "" {
		return "name is required"
	}
	if e.taken[n] {
		return "peer " + n + " already exists"
	}
	return ""
}

// nextField/prevField advance the focus, skipping the locked name field on a
// re-enroll form.
func (e enrollFormModal) nextField(cur int) int {
	n := (cur + 1) % efCount
	if e.reenroll && n == efName {
		n = (n + 1) % efCount
	}
	return n
}

func (e enrollFormModal) prevField(cur int) int {
	n := (cur - 1 + efCount) % efCount
	if e.reenroll && n == efName {
		n = (n - 1 + efCount) % efCount
	}
	return n
}

func (e *enrollFormModal) focusField() {
	e.name.Blur()
	e.user.Blur()
	e.address.Blur()
	switch e.field {
	case efName:
		e.name.Focus()
	case efUser:
		e.user.Focus()
	case efAddress:
		e.address.Focus()
	}
}

func (e enrollFormModal) handle(msg tea.KeyMsg) (modal, modalResult) {
	switch msg.String() {
	case "esc":
		return e, modalClose
	case "tab", "down":
		e.field = e.nextField(e.field)
		e.focusField()
		return e, modalKeep
	case "shift+tab", "up":
		e.field = e.prevField(e.field)
		e.focusField()
		return e, modalKeep
	case "enter":
		if e.field == efSubmit {
			if e.validateName() == "" {
				return e, modalSubmit
			}
			e.err = e.validateName()
			return e, modalKeep
		}
		// On any other field, enter advances like tab (and submits from the
		// last field), so the form is completable without reaching for tab.
		e.field = e.nextField(e.field)
		e.focusField()
		return e, modalKeep
	}

	switch e.field {
	case efGroups:
		return e.handlePick(msg, false), modalKeep
	case efAllowed:
		return e.handlePick(msg, true), modalKeep
	case efClient:
		if msg.String() == " " || msg.String() == "x" {
			e.client = !e.client
		}
		return e, modalKeep
	case efName:
		var cmd tea.Cmd
		e.name, cmd = e.name.Update(msg)
		_ = cmd
		// Surface a duplicate-name collision live as it is typed (not only on
		// submit); an empty/required name stays silent until submit so a fresh
		// field shows no error.
		if n := strings.TrimSpace(e.name.Value()); n != "" && e.taken[n] {
			e.err = "peer " + n + " already exists"
		} else {
			e.err = ""
		}
		return e, modalKeep
	case efUser:
		var cmd tea.Cmd
		e.user, cmd = e.user.Update(msg)
		_ = cmd
		return e, modalKeep
	case efAddress:
		var cmd tea.Cmd
		e.address, cmd = e.address.Update(msg)
		_ = cmd
		return e, modalKeep
	}
	return e, modalKeep
}

// handlePick moves the cursor / toggles a checkbox inside whichever inline
// picker (groups or allowed) currently has focus.
func (e enrollFormModal) handlePick(msg tea.KeyMsg, allowed bool) enrollFormModal {
	opts := e.groupOpts
	if allowed {
		opts = e.allowOpts
	}
	cur := &e.groupCur
	set := e.groupSet
	if allowed {
		cur = &e.allowCur
		set = e.allowSet
	}
	switch msg.String() {
	case "j":
		if len(opts) > 0 {
			*cur = clamp(*cur+1, 0, len(opts)-1)
		}
	case "k":
		if len(opts) > 0 {
			*cur = clamp(*cur-1, 0, len(opts)-1)
		}
	case " ", "x":
		if len(opts) > 0 {
			name := opts[*cur]
			set[name] = !set[name]
		}
	}
	return e
}

func (e enrollFormModal) selected(set map[string]bool, opts []string) []string {
	var out []string
	for _, o := range opts {
		if set[o] {
			out = append(out, o)
		}
	}
	return out
}

func (e enrollFormModal) view(w, _ int) []string {
	label := func(i int, s string) string {
		if e.field == i {
			return selStyle.Render("> " + s)
		}
		return "  " + s
	}
	pickLines := func(i int, opts []string, set map[string]bool, cur int) []string {
		focused := e.field == i
		if len(opts) == 0 {
			return []string{label(i, "(no groups exist)")}
		}
		out := make([]string, 0, len(opts))
		for j, o := range opts {
			box := "[ ]"
			if set[o] {
				box = "[x]"
			}
			marker := "    "
			if focused && j == cur {
				marker = "  > "
			}
			row := marker + box + " " + o
			if focused && j == cur {
				row = selStyle.Render(row)
			} else if set[o] {
				row = pickOnStyle.Render(row)
			}
			out = append(out, row)
		}
		return out
	}

	var lines []string
	if e.reenroll {
		lines = []string{
			"  name:    " + e.fixedName + " " + modalHintStyle.Render("(existing peer — fixed)"),
			modalHintStyle.Render("  nothing changes on the peer until the minted one-liner runs on it"),
		}
	} else {
		lines = []string{
			label(efName, "name:    "+e.name.View()),
		}
	}
	if e.err != "" {
		lines = append(lines, errStyle.Render("    ✗ "+e.err))
	}
	lines = append(lines, labelStyle.Render("  groups (space toggle, j/k move):"))
	lines = append(lines, pickLines(efGroups, e.groupOpts, e.groupSet, e.groupCur)...)
	lines = append(lines, labelStyle.Render("  allowed inbound:"))
	lines = append(lines, pickLines(efAllowed, e.allowOpts, e.allowSet, e.allowCur)...)
	lines = append(lines,
		label(efUser, "user:    "+e.user.View()),
		label(efAddress, "address: "+e.address.View()),
	)
	client := "[ ]"
	if e.client {
		client = "[x]"
	}
	lines = append(lines, label(efClient, "client (no inbound trust)  "+client))

	submit := "[ submit ]"
	if e.validateName() != "" {
		submit = modalHintStyle.Render("[ submit — name required/unique ]")
	} else if e.field == efSubmit {
		submit = okStyle.Render("[ submit ]")
	}
	lines = append(lines, "", label(efSubmit, submit))
	lines = append(lines, "", modalHintStyle.Render("tab/↑↓ field · space toggle · enter next/submit · esc cancel"))
	return lines
}

// startEnroll opens the enroll form. Gated by --read-only; the existing peer
// names are snapshotted into the name validator so a duplicate is rejected
// without a db round-trip (the mint still re-checks transactionally).
func (m Model) startEnroll() (tea.Model, tea.Cmd) {
	if !m.mutationsEnabled() || (m.view != viewPeers && m.view != viewGroups) {
		return m, nil
	}
	groups := selectableGroupNames(m.data.Groups)
	taken := make(map[string]bool, len(m.data.Peers))
	for _, p := range m.data.Peers {
		taken[p.Name] = true
	}
	m.pushModal(newEnrollFormModal(groups, taken))
	return m, nil
}

// startReenroll opens the pre-filled re-enroll form for the peer shown in the
// detail pane. Unlike plain enroll (which rejects taken names so a typo cannot
// silently become a re-key), re-enroll is only reachable from a specific
// peer's detail page. The manager's own row and revoked rows refuse with a
// footer notice, mirroring the ops-level guards.
func (m Model) startReenroll() (tea.Model, tea.Cmd) {
	if !m.mutationsEnabled() || m.view != viewPeers || !m.detail {
		return m, nil
	}
	p, ok := m.detailPeer()
	if !ok {
		return m, nil
	}
	if m.isSelfPeer(p.Name) {
		m.notice = "peer \"" + p.Name + "\" is certhold's own row — it cannot be re-enrolled"
		return m, nil
	}
	if p.Revoked {
		m.notice = "peer \"" + p.Name + "\" is revoked — it cannot be re-enrolled"
		return m, nil
	}
	m.pushModal(newReenrollFormModal(selectableGroupNames(m.data.Groups), p))
	return m, nil
}

// submitEnroll mints the enrollment. It pops the form, runs ops.MintEnroll
// through the action bridge (so a passphrase-protected CA prompts via the same
// modal path), and on success replaces the progress modal with the result
// screen carrying the full one-liner. MintEnroll is a single local mint, so it
// emits no per-peer events — the progress modal just shows done, then yields to
// the result screen handled in handleActionDone.
func (m Model) submitEnroll(e enrollFormModal) (tea.Model, tea.Cmd) {
	if e.validateName() != "" {
		return m, nil
	}
	m.popModal()
	spec := ops.EnrollSpec{
		Name:    strings.TrimSpace(e.name.Value()),
		Groups:  e.selected(e.groupSet, e.groupOpts),
		Allowed: e.selected(e.allowSet, e.allowOpts),
		User:    strings.TrimSpace(e.user.Value()),
		Address: strings.TrimSpace(e.address.Value()),
		Client:  e.client,
		BaseURL: enrollBaseURL(m.data.BaseURL),
	}
	heading := "enroll " + spec.Name
	if e.reenroll {
		// The pickers hide the manager principal (T162), so a peer that already
		// carries it — membership or allowed — keeps it across the re-enroll,
		// exactly like the u/i edit paths. The picker choices are explicit:
		// ClientSet/AllowedSet make the upsert apply them rather than fall back
		// to the defaults-from-DB path.
		spec.Name = e.fixedName
		spec.Groups = m.keepManagerGroup(e.fixedName, spec.Groups)
		spec.Allowed = m.keepManagerAllowed(e.fixedName, spec.Allowed)
		spec.ClientSet = true
		spec.AllowedSet = true
		heading = "re-enroll " + spec.Name
	}
	m.enrollPending = true
	m.enrollClient = spec.Client
	m.enrollResult.Store(nil)
	holder := m.enrollResult
	run := func(ctx context.Context, deps ops.Deps) error {
		res, err := ops.MintEnroll(ctx, deps, spec)
		if err != nil {
			return err
		}
		holder.Store(&res)
		return nil
	}
	return m.startAction(heading, run)
}

// enrollBaseURL mirrors the CLI's base-url normalization (trim trailing
// newline/slash) and falls back to the legacy default when no base_url file is
// present, so the one-liner is well-formed even on a fresh manager.
func enrollBaseURL(raw string) string {
	u := strings.TrimRight(strings.TrimSpace(raw), "\n/")
	if u == "" {
		return "https://certhold.home.lan"
	}
	return u
}
