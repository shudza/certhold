package tui

import "github.com/shudza/certhold/internal/peerfiles"

// selectableGroupNames is the option list every group picker is built from: the
// fleet's groups minus the implicit manager principal. Inbound access from the
// manager is granted unconditionally by peerfiles, and offering the principal as
// a membership option would mint it onto a regular peer, so the TUI never lets a
// picker grant or revoke it.
func selectableGroupNames(groups []groupRow) []string {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		if g.Name == peerfiles.ManagerPrincipal {
			continue
		}
		out = append(out, g.Name)
	}
	return out
}

// withManager re-adds the manager principal to a picker's result when the peer
// already carried it. The principal is hidden from the options, so a submit
// would otherwise silently strip a pre-existing manager entry (the manager's own
// allowed list, or a peer enrolled with --groups manager) from an unrelated edit.
func withManager(chosen []string, had bool) []string {
	if !had || isMember(chosen, peerfiles.ManagerPrincipal) {
		return chosen
	}
	return append(append([]string(nil), chosen...), peerfiles.ManagerPrincipal)
}

// keepManagerGroup preserves a peer's hidden manager MEMBERSHIP across an
// edit-groups submit.
func (m Model) keepManagerGroup(peer string, chosen []string) []string {
	p, ok := m.peerByName(peer)
	return withManager(chosen, ok && isMember(p.Groups, peerfiles.ManagerPrincipal))
}

// keepManagerAllowed preserves a peer's hidden manager ALLOWED-INBOUND entry
// across an edit-allowed submit.
func (m Model) keepManagerAllowed(peer string, chosen []string) []string {
	p, ok := m.peerByName(peer)
	return withManager(chosen, ok && isMember(p.Allowed, peerfiles.ManagerPrincipal))
}

// isSelfPeer reports whether name is the manager's own peer row. Group
// MEMBERSHIP there is meaningless — the manager reaches the fleet through the
// manager principal, which lives on its cert and in no group — and ops refuses
// the re-sign, so the membership paths drop the row instead of offering a
// guaranteed-error target. Allowed-inbound edits on the row stay available:
// they re-sign nothing.
func (m Model) isSelfPeer(name string) bool {
	return m.action.Hostname != "" && name == m.action.Hostname
}
