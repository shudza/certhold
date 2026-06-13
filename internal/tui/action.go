package tui

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/shudza/certhold/internal/ops"
)

// errPassphraseCanceled is returned to the ops goroutine's prompt when the
// operator dismisses the passphrase modal, so the in-flight action fails
// cleanly instead of leaving the worker blocked forever.
var errPassphraseCanceled = errors.New("passphrase entry canceled")

// ActionDeps is the seam cli/tui.go fills with real wiring and tests fill with
// fakes. BuildDeps receives the OnEvent sink and CAUnlock/PeerPass closures the
// TUI owns (they bridge to the passphrase modal) and returns a fully wired
// ops.Deps; Hostname is certhold's own peer name for revoke's rekey.
type ActionDeps struct {
	BuildDeps func(onEvent func(ops.Event), caUnlock, peerPass func() ([]byte, error)) ops.Deps
	Hostname  string
}

// passReq is one synchronous passphrase request raised from inside the ops
// goroutine. reply is buffered (cap 1) so the worker's send never blocks even
// if the event loop has already moved on.
type passReq struct {
	gen     int
	heading string
	prompt  string
	reply   chan passReply
}

type passReply struct {
	pass []byte
	err  error
}

// passPromptMsg is the tea message a reader-cmd produces when the ops goroutine
// asks for a passphrase; the Model opens (or re-decorates) the passphrase modal
// in response and remembers reply so a submit/cancel can answer the worker.
type passPromptMsg struct {
	req passReq
}

// passSession owns the per-Model passphrase channels. The ops goroutine's
// unlocker prompt sends a passReq on reqs and blocks on the request's own reply
// channel; the event loop reads reqs via waitPassReqCmd and never blocks on the
// worker, so the loop stays responsive to the modal's keystrokes — the modal's
// submit is what unblocks the worker. This is why neither side deadlocks: the
// only cross-goroutine wait is the worker blocking on reply, which a UI event
// (modal submit/cancel) always satisfies.
type passSession struct {
	unlocker *ops.SessionUnlocker
	reqs     atomic.Pointer[chan passReq] // per-action channel; rotated by arm
	gen      atomic.Int64                 // current action gen, stamped onto each request
}

func newPassSession() *passSession {
	s := &passSession{}
	ch := make(chan passReq, 1)
	s.reqs.Store(&ch)
	s.unlocker = ops.NewSessionUnlocker(s.promptCA)
	return s
}

// close retires the last action's reader and zeroes the cached CA passphrase at
// session exit. The final reader is the one re-armed by answerPassphrase that no
// subsequent arm() ever closed; closing the current channel here wakes it (!ok →
// nil) instead of leaving it blocked until process exit. Idempotent: a nil reqs
// pointer means it was already closed.
func (s *passSession) close() {
	if old := s.reqs.Swap(nil); old != nil {
		close(*old)
	}
	s.unlocker.Close()
}

// arm rotates in a fresh request channel for a new action and returns it, so a
// leaked waiter from a prior (completed) action — still blocked on the old
// channel — can never steal the new action's passphrase request. It also closes
// the prior channel, which retires any reader still blocked on it: waitReqCmd
// observes the closed channel (!ok) and returns nil, so the orphaned reader
// wakes and exits instead of blocking forever. The prior action's worker has
// already returned (it sent its terminal error before the next action could
// arm), so nothing is left to send on the closed channel.
func (s *passSession) arm() chan passReq {
	if old := s.reqs.Load(); old != nil {
		close(*old)
	}
	ch := make(chan passReq, 1)
	s.reqs.Store(&ch)
	return ch
}

// promptCA runs on the ops goroutine. It hands a request to the event loop and
// blocks until the modal answers. The request is stamped with the current
// action gen (set by runActionCmd) so a passPromptMsg from a superseded action
// — e.g. a stale re-armed waiter grabbing a retry's request — is recognized and
// dropped on arrival. SessionUnlocker caches the first non-error result, so
// this prompts at most once per session.
func (s *passSession) promptCA() ([]byte, error) {
	return s.prompt("CA passphrase: ")
}

// peerUnlocker is the manager-peer passphrase prompt. It reuses the CA modal/
// channel but is wired to its own unlocker so the two caches stay independent
// (matching the CLI's separate CA/peer unlockers).
func (s *passSession) peerUnlocker() *ops.SessionUnlocker {
	return ops.NewSessionUnlocker(func() ([]byte, error) {
		return s.prompt("Manager peer passphrase: ")
	})
}

func (s *passSession) prompt(label string) ([]byte, error) {
	reply := make(chan passReply, 1)
	ch := *s.reqs.Load()
	ch <- passReq{gen: int(s.gen.Load()), heading: "Unlock", prompt: label, reply: reply}
	r := <-reply
	return r.pass, r.err
}

// waitReqCmd captures the current action's request channel and blocks for the
// next passphrase request on it. A closed channel (next action armed) yields
// !ok, returning nil so the reader retires instead of leaking: this is what
// stops the one-reader-per-action leak the re-arm in answerPassphrase would
// otherwise create. Within a single action the channel stays open, so a second
// prompt (peer passphrase after CA) is delivered normally.
func (s *passSession) waitReqCmd() tea.Cmd {
	ch := *s.reqs.Load()
	return func() tea.Msg {
		req, ok := <-ch
		if !ok {
			return nil
		}
		return passPromptMsg{req: req}
	}
}

// runActionCmd launches an ops mutation on a goroutine, wiring its events and
// terminal error onto the bridge. The returned tea.Cmd batch starts the worker
// and the three reader-cmds (event, done, passphrase-request) that translate
// the worker's channels into tea messages.
func (m *Model) runActionCmd(run func(ctx context.Context, deps ops.Deps) error) tea.Cmd {
	m.actionGen++
	gen := m.actionGen
	m.pass.gen.Store(int64(gen))
	m.pass.arm()
	bridge := newActionBridge(gen)
	m.bridge = bridge

	deps := m.action.BuildDeps(
		func(e ops.Event) { bridge.events <- e },
		m.pass.unlocker.Get,
		m.peerPass.Get,
	)
	ctx := m.ctx

	worker := func() tea.Msg {
		err := run(ctx, deps)
		bridge.done <- err
		close(bridge.events)
		return nil
	}
	return tea.Batch(worker, bridge.waitEventCmd(), bridge.waitDoneCmd(), m.pass.waitReqCmd())
}

func (m *Model) pushModal(mo modal) { m.modals = append(m.modals, mo) }

func (m *Model) popModal() {
	if n := len(m.modals); n > 0 {
		m.modals = m.modals[:n-1]
	}
}

func (m *Model) replaceTop(mo modal) {
	if n := len(m.modals); n > 0 {
		m.modals[n-1] = mo
	}
}

// startEditGroups opens the multi-pick of existing groups, pre-checked with the
// selected peer's current membership. Read-only or a missing selection is a
// no-op (no modal opens), satisfying the --read-only gate.
func (m Model) startEditGroups() (tea.Model, tea.Cmd) {
	if !m.mutationsEnabled() || m.view != viewPeers || m.detail {
		return m, nil
	}
	p, ok := m.selectedPeer()
	if !ok || p.Revoked {
		return m, nil
	}
	opts := make([]string, 0, len(m.data.Groups))
	for _, g := range m.data.Groups {
		opts = append(opts, g.Name)
	}
	m.pushModal(newPickModal("edit groups: "+p.Name, p.Name, opts, p.Groups))
	return m, nil
}

func (m Model) startRevoke() (tea.Model, tea.Cmd) {
	if !m.mutationsEnabled() || m.view != viewPeers {
		return m, nil
	}
	p, ok := m.selectedPeer()
	if !ok || p.Revoked {
		return m, nil
	}
	m.pushModal(confirmModal{
		heading: "revoke " + p.Name,
		subject: p.Name,
		kind:    confirmRevoke,
		body: []string{
			"Revoke peer " + p.Name + " and rekey the CA to exclude it?",
			"This rotates the CA across all remaining inbound peers.",
		},
	})
	return m, nil
}

// handleModalKey routes a key to the top modal and acts on its result. A
// submit on the pick/confirm modal launches the corresponding ops action;
// passphrase/progress submits are handled by their own paths.
func (m Model) handleModalKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "ctrl+c" {
		return m, tea.Quit
	}
	top, ok := m.topModal()
	if !ok {
		return m, nil
	}
	next, res := top.handle(msg)
	switch res {
	case modalKeep:
		m.replaceTop(next)
		return m, nil
	case modalClose:
		m.popModal()
		if pm, isPass := next.(passphraseModal); isPass {
			return m.answerPassphrase(passReply{err: errPassphraseCanceled}, pm)
		}
		return m, nil
	case modalSubmit:
		return m.submitModal(next)
	}
	return m, nil
}

func (m Model) submitModal(top modal) (tea.Model, tea.Cmd) {
	switch mo := top.(type) {
	case confirmModal:
		m.popModal()
		if mo.kind == confirmGroupDelete {
			return m.launchGroupDelete(mo.subject)
		}
		return m.launchRevoke(mo.subject)
	case pickModal:
		m.popModal()
		switch mo.kind {
		case pickGroupMembers:
			return m.launchMembership(mo)
		case pickPeerAllowed:
			return m.launchAllowed(mo.subject, mo.selected())
		default:
			return m.launchEditGroups(mo.subject, mo.selected())
		}
	case textModal:
		m.popModal()
		return m.submitText(mo)
	case passphraseModal:
		m.popModal()
		return m.answerPassphrase(passReply{pass: []byte(mo.input.Value())}, mo)
	}
	return m, nil
}

func (m Model) launchEditGroups(name string, groups []string) (tea.Model, tea.Cmd) {
	run := func(ctx context.Context, deps ops.Deps) error {
		return ops.UpdatePeer(ctx, deps, name, groups, "")
	}
	return m.startAction("update "+name, run)
}

func (m Model) launchRevoke(name string) (tea.Model, tea.Cmd) {
	hostname := m.action.Hostname
	run := func(ctx context.Context, deps ops.Deps) error {
		return ops.RevokePeer(ctx, deps, name, hostname)
	}
	return m.startAction("revoke "+name, run)
}

// startAction records the action so a wrong-passphrase retry can re-run it,
// opens the progress modal, and launches the worker + reader-cmds.
func (m Model) startAction(heading string, run func(ctx context.Context, deps ops.Deps) error) (tea.Model, tea.Cmd) {
	m.lastRun = run
	m.lastHeading = heading
	m.pushModal(newProgressModal(heading))
	return m, m.runActionCmd(run)
}

// isPassphraseError reports whether err looks like a CA/peer-key decrypt
// failure, the only error class the passphrase retry path should re-prompt for.
func isPassphraseError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "passphrase") ||
		strings.Contains(s, "decrypt") ||
		strings.Contains(s, "incorrect") ||
		strings.Contains(s, "load ca")
}

// handlePassPrompt opens the passphrase modal for a request raised by the ops
// goroutine and remembers the reply channel. A stale request (gen mismatch) is
// answered with an error so the orphaned worker unblocks.
func (m Model) handlePassPrompt(msg passPromptMsg) (tea.Model, tea.Cmd) {
	if msg.req.gen != m.actionGen {
		msg.req.reply <- passReply{err: errPassphraseCanceled}
		return m, nil
	}
	pm := newPassphraseModal(msg.req.heading, msg.req.prompt)
	pm.reply = msg.req.reply
	pm.errMsg = m.passErr
	m.passErr = ""
	// The passphrase modal sits above the (already-pushed) progress modal so
	// a submit feeds the blocked worker; on dismissal answerPassphrase fails
	// the worker and the progress modal renders the cancellation.
	m.pushModal(pm)
	return m, nil
}

// answerPassphrase feeds the worker's reply channel and either re-arms the
// waiter (so a wrong passphrase can be retried) or lets the action proceed.
// On a successful submit we keep waiting for the next request the same worker
// might raise (e.g. peer passphrase after CA), so one action can prompt twice.
func (m Model) answerPassphrase(r passReply, pm passphraseModal) (tea.Model, tea.Cmd) {
	if pm.reply != nil {
		pm.reply <- r
	}
	if r.err != nil {
		return m, nil
	}
	return m, m.pass.waitReqCmd()
}

func (m Model) handleActionEvent(msg actionEventMsg) (tea.Model, tea.Cmd) {
	if msg.gen != m.actionGen {
		return m, nil
	}
	// The progress modal may not be on top (a passphrase modal for a second
	// prompt can sit above it), so fold the event into it wherever it is.
	if i := m.progressIndex(); i >= 0 {
		m.modals[i] = m.modals[i].(progressModal).appendEvent(msg.event)
	}
	return m, m.bridge.waitEventCmd()
}

// handleActionDone closes out the action: it surfaces a wrong-passphrase (or
// any) error back into the originating modal so the operator can retry, marks
// the progress modal done, and triggers a data reload so the table reflects the
// mutation after auto-reload.
func (m Model) handleActionDone(msg actionDoneMsg) (tea.Model, tea.Cmd) {
	if msg.gen != m.actionGen {
		return m, nil
	}
	idx := m.progressIndex()
	if idx < 0 {
		return m, nil
	}
	// A wrong passphrase fails the whole action; forget the bad cache, drop
	// the failed progress modal (and anything above it), and re-launch under a
	// fresh progress modal. handlePassPrompt reopens the passphrase modal
	// carrying passErr, so the retry happens in place.
	if msg.err != nil && isPassphraseError(msg.err) && !errors.Is(msg.err, errPassphraseCanceled) {
		m.pass.unlocker.Forget()
		m.peerPass.Forget()
		m.modals = m.modals[:idx]
		m.passErr = msg.err.Error()
		return m.startAction(m.lastHeading, m.lastRun)
	}
	m.modals = m.modals[:idx+1] // discard any modal stranded above the progress
	pm := m.modals[idx].(progressModal)
	pm.done = true
	pm.err = msg.err
	m.modals[idx] = pm
	return m, m.reloadCmd()
}

func (m Model) progressIndex() int {
	for i := len(m.modals) - 1; i >= 0; i-- {
		if _, ok := m.modals[i].(progressModal); ok {
			return i
		}
	}
	return -1
}
