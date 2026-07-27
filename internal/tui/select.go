package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/shudza/certhold/internal/ops"
)

// markMax caps how many target peers a batch confirm modal lists before it
// collapses the tail into a "+N more" line, matching the table's width-clamp
// discipline so a 50-mark batch never blows the modal past the frame.
const markMax = 8

// toggleMark flips the selected peer's mark. Marks are keyed by peer NAME, not
// row index, so a mark is on the peer and survives a filter change (the row it
// sits on may scroll out of the filtered view, but the name stays marked). A
// no-op when no peer is selectable.
func (m *Model) toggleMark() {
	p, ok := m.selectedPeer()
	if !ok {
		return
	}
	if m.marks == nil {
		m.marks = map[string]bool{}
	}
	if m.marks[p.Name] {
		delete(m.marks, p.Name)
	} else {
		m.marks[p.Name] = true
	}
}

// markedNames returns the marked peers in the data's stable order. Order tracks
// m.data.Peers (not the filtered view) so a batch run touches every marked peer
// regardless of the current filter. Revoked peers are NOT filtered here — the
// launchers (startRevoke/launchBatch*) drop already-revoked names so a batch
// never re-revokes one; a mark whose name no longer has a row yields no target.
func (m Model) markedNames() []string {
	if len(m.marks) == 0 {
		return nil
	}
	out := make([]string, 0, len(m.marks))
	for _, p := range m.data.Peers {
		if m.marks[p.Name] {
			out = append(out, p.Name)
		}
	}
	return out
}

// batchOutcome is the worker's report the value-type Model copy reads when the
// batch finishes: the peers that failed keep their mark for a retry, everything
// else is cleared. It is written once by the worker and read once by
// handleActionDone, so a single atomic pointer (allocated per batch) carries it
// across the goroutine boundary the same way enrollResult does for the mint.
type batchOutcome struct {
	failed []string
}

// startBatch builds the aggregated run closure over the marked set for a per-
// peer op and opens ONE progress modal. It reuses startAction (and therefore
// the same progress + passphrase bridges) exactly like launchMembership: N
// sequential ops, one events channel, one done. label is the per-peer action
// verb ("revoke"/"update") and op is the per-peer mutation; both run on the ops
// goroutine. The outcome holder lets handleActionDone clear marks on the peers
// that succeeded while leaving failed peers marked.
func (m Model) startBatch(verb string, names []string, op func(ctx context.Context, deps ops.Deps, name string) error) (tea.Model, tea.Cmd) {
	outcome := &atomic.Pointer[batchOutcome]{}
	m.batchOutcome = outcome
	targets := append([]string(nil), names...)

	run := func(ctx context.Context, deps ops.Deps) error {
		var failed []string
		quiet := deps
		quiet.OnEvent = nil // the inner op's fleet-wide chatter is suppressed; the
		// batch emits its own per-target ✓/✗ lines so the transcript reads as one
		// line per marked peer regardless of how many peers each op touches.
		for _, name := range targets {
			if deps.OnEvent != nil {
				deps.OnEvent(ops.Event{Type: ops.EventPeerStart, Peer: name})
			}
			if err := op(ctx, quiet, name); err != nil {
				// A wrong CA/peer passphrase aborts the whole batch instead of
				// marking every peer failed: returning it directly lets
				// handleActionDone's retry branch re-prompt once and re-run the
				// entire batch in place (the unlocker never cached the bad value),
				// matching the single-peer retry. Nothing has been marked yet, so
				// the outcome holder is left nil → all marks survive for the retry.
				//
				// Why the whole-batch rerun is safe: a passphrase-class error can
				// surface AFTER some targets have already mutated, so the rerun
				// re-applies already-done targets. The default revoke path clears
				// the peer over SSH (the manager peer-key passphrase, deps.PeerPass,
				// is prompted at DIAL time) and only deletes the row on a successful
				// clear; UpdatePeer prompts the same passphrase at PUSH time, AFTER
				// its re-sign DB write. In both ops the passphrase prompt for a given
				// target precedes that target's committing mutation, so a bad
				// passphrase cannot leave a half-applied target.
				// The rerun is nonetheless end-state-correct because each batchable
				// op converges: a re-cleared+re-deleted peer that an earlier batch
				// iteration already removed simply fails its GetPeer with
				// ErrPeerNotFound on the rerun (recorded as a per-peer failure, not a
				// corruption), and UpdatePeer's re-sign+re-push converges on the same
				// group set. A future op whose rerun is NOT idempotent must store
				// partial successes before returning a passphrase error.
				if isPassphraseError(err) {
					return err
				}
				failed = append(failed, name)
				if deps.OnEvent != nil {
					deps.OnEvent(ops.Event{Type: ops.EventPeerFailed, Peer: name, Err: err})
				}
				continue
			}
			if deps.OnEvent != nil {
				deps.OnEvent(ops.Event{Type: ops.EventPeerDone, Peer: name, Msg: verb + " " + name})
			}
		}
		outcome.Store(&batchOutcome{failed: failed})
		if deps.OnEvent != nil {
			deps.OnEvent(ops.Event{Type: ops.EventInfo, Peer: "",
				Msg: fmt.Sprintf("%d ok, %d failed", len(targets)-len(failed), len(failed))})
		}
		if len(failed) > 0 {
			return fmt.Errorf("%d of %d failed: %s", len(failed), len(targets), strings.Join(failed, ","))
		}
		return nil
	}
	return m.startAction(fmt.Sprintf("batch %s (%d peers)", verb, len(targets)), run)
}

// launchBatchRevoke fans RevokePeer over every (live) marked peer. Each peer's
// revoke runs sequentially; a failure on one is recorded and the loop continues.
func (m Model) launchBatchRevoke() (tea.Model, tea.Cmd) {
	names := m.markedNames()
	var live []string
	for _, n := range names {
		if p, ok := m.peerByName(n); ok && !p.Revoked {
			live = append(live, n)
		}
	}
	if len(live) == 0 {
		return m, nil
	}
	hostname := m.action.Hostname
	op := func(ctx context.Context, deps ops.Deps, name string) error {
		return ops.RevokePeer(ctx, deps, name, hostname, false)
	}
	return m.startBatch("revoke", live, op)
}

// launchBatchRemove fans the DB-only RemovePeer over every marked peer. Unlike
// revoke this contacts no host; a missing row is recorded as a per-peer failure
// and the loop continues. An empty marked set is a no-op.
func (m Model) launchBatchRemove() (tea.Model, tea.Cmd) {
	names := m.markedNames()
	if len(names) == 0 {
		return m, nil
	}
	op := func(ctx context.Context, deps ops.Deps, name string) error {
		return ops.RemovePeer(ctx, deps, name)
	}
	return m.startBatch("remove", names, op)
}

// launchBatchEditGroups assigns the chosen group SET to every marked peer
// (absolute UpdatePeer), skipping revoked peers. An empty marked set is a no-op.
// The set is resolved per peer so a target that already holds the hidden manager
// principal keeps it, while the others never gain it.
func (m Model) launchBatchEditGroups(groups []string) (tea.Model, tea.Cmd) {
	names := m.markedNames()
	var live []string
	for _, n := range names {
		if p, ok := m.peerByName(n); ok && !p.Revoked {
			live = append(live, n)
		}
	}
	if len(live) == 0 {
		return m, nil
	}
	byPeer := make(map[string][]string, len(live))
	for _, n := range live {
		byPeer[n] = m.keepManagerGroup(n, groups)
	}
	hostname := m.action.Hostname
	op := func(ctx context.Context, deps ops.Deps, name string) error {
		return ops.UpdatePeer(ctx, deps, name, byPeer[name], "", hostname)
	}
	return m.startBatch("update", live, op)
}

// launchBatchMembers drives the picker's chosen peer set into the group as a
// batch: one UpdatePeer per CHANGED peer (added gains the group, removed loses
// it), like membershipDeltas but each delta is a batch target so a per-peer
// failure is recorded and the run continues. A no-op diff opens no action.
func (m Model) launchBatchMembers(mo pickModal) (tea.Model, tea.Cmd) {
	deltas := m.membershipDeltas(mo.subject, mo.selected())
	if len(deltas) == 0 {
		return m, nil
	}
	byPeer := make(map[string][]string, len(deltas))
	names := make([]string, 0, len(deltas))
	for _, d := range deltas {
		byPeer[d.peer] = d.newGroups
		names = append(names, d.peer)
	}
	hostname := m.action.Hostname
	op := func(ctx context.Context, deps ops.Deps, name string) error {
		return ops.UpdatePeer(ctx, deps, name, byPeer[name], "", hostname)
	}
	return m.startBatch("update", names, op)
}

// batchConfirmBody renders the target list for a batch confirm modal, clamped to
// markMax with a "+N more" tail so a large marked set never overflows the frame.
func batchConfirmBody(head string, names []string) []string {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	body := []string{head}
	shown := sorted
	if len(sorted) > markMax {
		shown = sorted[:markMax]
	}
	for _, n := range shown {
		body = append(body, "  • "+n)
	}
	if len(sorted) > markMax {
		body = append(body, dimStyle.Render(fmt.Sprintf("  +%d more", len(sorted)-markMax)))
	}
	return body
}
