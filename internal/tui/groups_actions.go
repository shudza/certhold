package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/shudza/certhold/internal/ops"
)

// textKind tags which action a textModal's submit launches.
type textKind int

const (
	textCreateGroup textKind = iota
	textRenameGroup
	textEditAddress
)

// textModal is a single-line free-text prompt (group name entry). Unlike
// passphraseModal it echoes its value; subject names the existing group a
// rename acts on (empty for create).
type textModal struct {
	heading string
	kind    textKind
	subject string
	input   textinput.Model
}

func newTextModal(heading, prompt, initial string, kind textKind, subject string) textModal {
	ti := textinput.New()
	ti.Prompt = prompt
	// bubbles truncates in SetValue too, so a CharLimit below the stored value's
	// length would silently corrupt a prefilled address on an untouched submit.
	// Addresses get the validator's 255-byte budget; group names stay short.
	if kind == textEditAddress {
		ti.CharLimit = 255
	} else {
		ti.CharLimit = 64
	}
	ti.SetValue(initial)
	ti.CursorEnd()
	ti.Focus()
	return textModal{heading: heading, kind: kind, subject: subject, input: ti}
}

func (t textModal) title() string { return t.heading }

func (t textModal) handle(msg tea.KeyMsg) (modal, modalResult) {
	switch msg.String() {
	case "enter":
		return t, modalSubmit
	case "esc":
		return t, modalClose
	}
	var cmd tea.Cmd
	t.input, cmd = t.input.Update(msg)
	_ = cmd
	return t, modalKeep
}

func (t textModal) view(int, int) []string {
	return []string{
		t.input.View(),
		"",
		modalHintStyle.Render("enter submit · esc cancel"),
	}
}

// startCreateGroup opens the name-entry modal for a new group.
func (m Model) startCreateGroup() (tea.Model, tea.Cmd) {
	if !m.mutationsEnabled() || m.view != viewGroups {
		return m, nil
	}
	m.pushModal(newTextModal("create group", "name: ", "", textCreateGroup, ""))
	return m, nil
}

// startRenameGroup opens the name-entry modal seeded with the selected group's
// current name. A missing selection is a no-op.
func (m Model) startRenameGroup() (tea.Model, tea.Cmd) {
	if !m.mutationsEnabled() || m.view != viewGroups {
		return m, nil
	}
	g, ok := m.selectedGroup()
	if !ok {
		return m, nil
	}
	if isReservedGroup(g.Name) {
		m.notice = reservedGroupNotice("it cannot be renamed")
		return m, nil
	}
	m.pushModal(newTextModal("rename "+g.Name, "new name: ", g.Name, textRenameGroup, g.Name))
	return m, nil
}

// startDeleteGroup opens a confirm modal whose body spells out the cascade the
// delete will push: members re-signed without the group, allowing peers'
// authorized_keys rewritten.
func (m Model) startDeleteGroup() (tea.Model, tea.Cmd) {
	if !m.mutationsEnabled() || m.view != viewGroups {
		return m, nil
	}
	g, ok := m.selectedGroup()
	if !ok {
		return m, nil
	}
	if isReservedGroup(g.Name) {
		m.notice = reservedGroupNotice("it cannot be deleted")
		return m, nil
	}
	body := []string{"Delete group " + g.Name + "?"}
	if len(g.Members) > 0 {
		body = append(body, fmt.Sprintf("members re-signed + pushed (%d): %s", len(g.Members), joinOrDash(g.Members)))
	}
	if len(g.AllowedBy) > 0 {
		body = append(body, fmt.Sprintf("allowed-by rewrites (%d): %s", len(g.AllowedBy), joinOrDash(g.AllowedBy)))
	}
	if len(g.Members) == 0 && len(g.AllowedBy) == 0 {
		body = append(body, "no peers affected")
	}
	m.pushModal(confirmModal{heading: "delete " + g.Name, subject: g.Name, kind: confirmGroupDelete, body: body})
	return m, nil
}

// startGroupMembership opens the peer multi-pick pre-checked with the selected
// group's current members; submit diffs against that snapshot.
func (m Model) startGroupMembership() (tea.Model, tea.Cmd) {
	if !m.mutationsEnabled() || m.view != viewGroups {
		return m, nil
	}
	g, ok := m.selectedGroup()
	if !ok {
		return m, nil
	}
	// The reserved row is refused before the marked-set branch, so a batch's
	// marks survive the refusal and can be aimed at a real group instead.
	if isReservedGroup(g.Name) {
		m.notice = reservedGroupNotice("membership cannot be edited from the TUI")
		return m, nil
	}
	opts := make([]string, 0, len(m.data.Peers))
	for _, p := range m.data.Peers {
		if p.Revoked || m.isSelfPeer(p.Name) {
			continue
		}
		opts = append(opts, p.Name)
	}
	// With peers marked, m drives the marked SET into the selected group: the
	// picker opens pre-checked with current members AND the marked peers, so the
	// operator confirms the union (or trims) before the batch fans out. batchKind
	// routes submit to launchBatchMembers, which assigns every chosen peer to the
	// group via batch UpdatePeer (continue-on-error, one progress modal).
	if names := m.markedNames(); len(names) > 0 {
		pre := m.membershipPre(g.Members)
		seen := map[string]bool{}
		for _, p := range pre {
			seen[p] = true
		}
		for _, n := range names {
			if p, ok := m.peerByName(n); ok && !p.Revoked && !seen[n] && !m.isSelfPeer(n) {
				pre = append(pre, n)
			}
		}
		m.batchKind = batchMembers
		m.pushModal(newPickModalKind(pickGroupMembers, "members of "+g.Name+" (+marked)", g.Name, opts, pre))
		return m, nil
	}
	m.batchKind = batchNone
	m.pushModal(newPickModalKind(pickGroupMembers, "members of "+g.Name, g.Name, opts, m.membershipPre(g.Members)))
	return m, nil
}

// membershipPre is the members picker's pre-checked set: the group's current
// members minus the manager's self row, which the options omit. A legacy self
// membership (added by CLI before the row was guarded) would otherwise open
// pre-checked-but-unlistable and submit as a removal ops refuses.
func (m Model) membershipPre(members []string) []string {
	pre := make([]string, 0, len(members))
	for _, name := range members {
		if m.isSelfPeer(name) {
			continue
		}
		pre = append(pre, name)
	}
	return pre
}

// startEditAllowed opens the peer-side allowed-inbound multi-pick pre-checked
// with the selected peer's current allowed groups.
func (m Model) startEditAllowed() (tea.Model, tea.Cmd) {
	if !m.mutationsEnabled() || m.view != viewPeers || m.detail {
		return m, nil
	}
	p, ok := m.selectedPeer()
	if !ok || p.Revoked {
		return m, nil
	}
	opts := selectableGroupNames(m.data.Groups)
	m.pushModal(newPickModalKind(pickPeerAllowed, "allowed inbound: "+p.Name, p.Name, opts, p.Allowed))
	return m, nil
}

func (m Model) submitText(t textModal) (tea.Model, tea.Cmd) {
	name := strings.TrimSpace(t.input.Value())
	switch t.kind {
	case textCreateGroup:
		if name == "" {
			return m, nil
		}
		run := func(ctx context.Context, deps ops.Deps) error {
			return ops.GroupCreate(ctx, deps, name)
		}
		return m.startAction("create "+name, run)
	case textRenameGroup:
		if name == "" || name == t.subject {
			return m, nil
		}
		old, hostname := t.subject, m.action.Hostname
		run := func(ctx context.Context, deps ops.Deps) error {
			return ops.GroupRename(ctx, deps, old, name, hostname)
		}
		return m.startAction("rename "+old+" → "+name, run)
	case textEditAddress:
		peer := t.subject
		run := func(ctx context.Context, deps ops.Deps) error {
			return ops.SetPeerAddress(ctx, deps, peer, name)
		}
		return m.startAction("address "+peer, run)
	}
	return m, nil
}

func (m Model) launchGroupDelete(name string) (tea.Model, tea.Cmd) {
	hostname := m.action.Hostname
	run := func(ctx context.Context, deps ops.Deps) error {
		return ops.GroupDelete(ctx, deps, name, hostname)
	}
	return m.startAction("delete "+name, run)
}

func (m Model) launchAllowed(name string, groups []string) (tea.Model, tea.Cmd) {
	hostname := m.action.Hostname
	run := func(ctx context.Context, deps ops.Deps) error {
		return ops.SetPeerAllowedGroups(ctx, deps, name, groups, "", hostname)
	}
	return m.startAction("allowed "+name, run)
}

// membershipDelta is one peer whose membership of the edited group flips, with
// the full new group list ops.UpdatePeer must re-sign it against.
type membershipDelta struct {
	peer      string
	newGroups []string
}

// membershipDeltas diffs the picker's selection against its pre-checked snapshot
// and returns one delta per CHANGED peer only — added peers gain the group,
// removed peers lose it. Unchanged peers produce no delta, so launchMembership
// never re-signs or pushes them. Revoked peers and the manager's self row are
// never deltas: ops refuses a self-row re-sign. The new group list is computed
// off each peer's current groups in m.data (the load that opened the picker).
func (m Model) membershipDeltas(group string, selected []string) []membershipDelta {
	want := make(map[string]bool, len(selected))
	for _, p := range selected {
		want[p] = true
	}
	var deltas []membershipDelta
	for _, p := range m.data.Peers {
		if p.Revoked || m.isSelfPeer(p.Name) {
			continue
		}
		was := isMember(p.Groups, group)
		now := want[p.Name]
		if was == now {
			continue
		}
		var ng []string
		if now {
			ng = append(append([]string(nil), p.Groups...), group)
		} else {
			ng = removeString(p.Groups, group)
		}
		deltas = append(deltas, membershipDelta{peer: p.Name, newGroups: ng})
	}
	return deltas
}

// launchMembership applies the pre-checked picker's diff: one ops.UpdatePeer per
// changed peer, all inside a single action so the progress modal aggregates
// every peer's events. Unchanged peers are never touched. A no-op diff opens no
// action (the picker just closes).
func (m Model) launchMembership(mo pickModal) (tea.Model, tea.Cmd) {
	deltas := m.membershipDeltas(mo.subject, mo.selected())
	if len(deltas) == 0 {
		return m, nil
	}
	hostname := m.action.Hostname
	run := func(ctx context.Context, deps ops.Deps) error {
		var failed []string
		for _, d := range deltas {
			if err := ops.UpdatePeer(ctx, deps, d.peer, d.newGroups, "", hostname); err != nil {
				failed = append(failed, d.peer)
			}
		}
		if len(failed) > 0 {
			return fmt.Errorf("membership update incomplete: %s", strings.Join(failed, ","))
		}
		return nil
	}
	return m.startAction("members of "+mo.subject, run)
}

func isMember(groups []string, g string) bool {
	for _, x := range groups {
		if x == g {
			return true
		}
	}
	return false
}

func removeString(xs []string, v string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}
