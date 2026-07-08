package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/shudza/certhold/internal/ops"
)

// errPassphraseCanceled is returned to the ops goroutine's prompt when the
// operator dismisses the passphrase modal, so the in-flight action fails
// cleanly instead of leaving the worker blocked forever.
var errPassphraseCanceled = errors.New("passphrase entry canceled")

// errHostKeyRejected is returned to the ops goroutine's dial when the operator
// answers no to the host-key modal (or the session is closing with a prompt
// inflight), so the unknown-host dial fails cleanly instead of leaving the
// worker blocked forever.
var errHostKeyRejected = errors.New("host key rejected")

// ActionDeps is the seam cli/tui.go fills with real wiring and tests fill with
// fakes. BuildDeps receives the OnEvent sink, the CAUnlock/PeerPass closures the
// TUI owns (they bridge to the passphrase modal), and the hostKeyConfirm closure
// (it bridges to the host-key modal), and returns a fully wired ops.Deps;
// Hostname is certhold's own peer name for revoke's rekey.
type ActionDeps struct {
	BuildDeps func(onEvent func(ops.Event), caUnlock, peerPass func() ([]byte, error), hostKeyConfirm func(host, fingerprint, keyType string) (bool, error)) ops.Deps
	Hostname  string
}

// passReq is one synchronous passphrase request raised from inside the ops
// goroutine. reply is buffered (cap 1) so the worker's send never blocks even
// if the event loop has already moved on.
type passReq struct {
	gen     int
	heading string
	prompt  string
	// errMsg pre-decorates the modal with a prior-attempt note (e.g. the rotate
	// passphrase mismatch); empty for a clean prompt.
	errMsg string
	reply  chan passReply
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

// hostKeyReq is one synchronous host-key confirmation raised from inside the ops
// goroutine's dial (deps.HostKeyConfirm) when a peer presents an unknown host
// key. reply is buffered (cap 1) so the worker's send never blocks even if the
// event loop has already moved on. It rides the same arm/gen lifecycle and mu
// latch as passReq, so a stale prompt is dropped and a parked worker is canceled
// on session close exactly as the passphrase path is.
type hostKeyReq struct {
	gen         int
	host        string
	fingerprint string
	keyType     string
	reply       chan hostKeyReply
}

type hostKeyReply struct {
	ok  bool
	err error
}

// hostKeyPromptMsg is the tea message a reader-cmd produces when the ops dial
// asks the operator to verify an unknown host key; the Model opens the host-key
// modal and remembers reply so a yes/no can answer the worker.
type hostKeyPromptMsg struct {
	req hostKeyReq
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
	reqs     atomic.Pointer[chan passReq]   // per-action channel; rotated by arm
	gen      atomic.Int64                   // current action gen, stamped onto each request
	inflight atomic.Pointer[chan passReply] // the reply chan a worker is parked on, if any
	// hkReqs/hkInflight mirror reqs/inflight for the host-key confirm prompt.
	// They share mu and the closed latch so confirmHostKey's send and inflight
	// publish obey the exact same race discipline as promptErr, and one close()
	// cancels a worker parked on either prompt. hkReqs is rotated by arm() so a
	// stale dial-confirm from a superseded action can never steal the live one.
	hkReqs     atomic.Pointer[chan hostKeyReq]
	hkInflight atomic.Pointer[chan hostKeyReply]
	// mu serializes promptErr's send-on-reqs against the close()/arm() that retire
	// that same channel, so a worker's send can never race (or panic on) a close.
	// closed latches at session teardown so a late worker abandons its send.
	mu     sync.Mutex
	closed bool
}

func newPassSession() *passSession {
	s := &passSession{}
	ch := make(chan passReq, 1)
	s.reqs.Store(&ch)
	hk := make(chan hostKeyReq, 1)
	s.hkReqs.Store(&hk)
	s.unlocker = ops.NewSessionUnlocker(s.promptCA)
	return s
}

// close retires the last action's reader and zeroes the cached CA passphrase at
// session exit. The final reader is the one re-armed by answerPassphrase that no
// subsequent arm() ever closed; closing the current channel here wakes it (!ok →
// nil) instead of leaving it blocked until process exit. A worker parked on a
// passphrase reply is canceled first: it holds the unlocker lock while blocked,
// so unlocker.Close() would deadlock against it otherwise (the common case when
// a test's drain ends with the modal still open). The reply chan is buffered
// (cap 1) so this send never blocks; a benign no-op if the modal already
// answered. Idempotent: a nil reqs pointer means it was already closed.
func (s *passSession) close() {
	s.mu.Lock()
	s.closed = true
	// Cancel a parked worker under the same lock that latches closed and that
	// promptErr publishes inflight under. This is what makes the handoff race-free:
	// a worker either published inflight before close took mu (we see it here and
	// cancel it) or it takes mu after us and sees closed (it abandons its send and
	// never parks). Without the shared lock close could swap a still-nil inflight
	// while the worker goes on to park forever.
	if rp := s.inflight.Swap(nil); rp != nil {
		select {
		case *rp <- passReply{err: errPassphraseCanceled}:
		default:
		}
	}
	// Cancel a host-key prompt parked under the same lock, for the same reason:
	// the worker either published hkInflight before close took mu (canceled here)
	// or it takes mu after us, sees closed, and abandons its send.
	if rp := s.hkInflight.Swap(nil); rp != nil {
		select {
		case *rp <- hostKeyReply{err: errHostKeyRejected}:
		default:
		}
	}
	old := s.reqs.Swap(nil)
	oldHK := s.hkReqs.Swap(nil)
	s.mu.Unlock()
	if old != nil {
		close(*old)
	}
	if oldHK != nil {
		close(*oldHK)
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
// arm), so nothing is left to send on the closed channel — except a host-key
// confirm: it runs on the SSH handshake goroutine inside the dial, which
// OUTLIVES the worker when the dial is abandoned (timeout/cancel), so a parked
// hkInflight must be rejected here or that goroutine leaks for the session.
func (s *passSession) arm() chan passReq {
	ch := make(chan passReq, 1)
	hk := make(chan hostKeyReq, 1)
	s.mu.Lock()
	if rp := s.hkInflight.Swap(nil); rp != nil {
		select {
		case *rp <- hostKeyReply{err: errHostKeyRejected}:
		default:
		}
	}
	old := s.reqs.Swap(&ch)
	oldHK := s.hkReqs.Swap(&hk)
	s.mu.Unlock()
	if old != nil {
		close(*old)
	}
	if oldHK != nil {
		close(*oldHK)
	}
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
	return s.promptLabeled("Unlock", label)
}

// promptLabeled is the general form behind prompt: it raises a passReq with a
// caller-chosen heading/prompt and blocks on its reply. The rekey rotate-
// passphrase source uses it to ask for a new passphrase (and its confirmation)
// through the very same modal channel CAUnlock rides, so a single arm/launch
// path serves both without a second bridge.
func (s *passSession) promptLabeled(heading, label string) ([]byte, error) {
	return s.promptErr(heading, label, "")
}

func (s *passSession) promptErr(heading, label, errMsg string) ([]byte, error) {
	reply := make(chan passReply, 1)
	defer s.inflight.Store(nil)
	// Both the send and the inflight publish run under mu, so this can never race
	// the close()/arm() that retire the request channel: once closed is latched (or
	// reqs cleared) the worker abandons its send instead of sending on a closed
	// channel. Publishing inflight under the same lock close cancels it under closes
	// the missed-cancel window — close either sees this reply chan (and cancels it)
	// or the worker sees closed first (and never parks). The channel is buffered
	// (cap 1) and per-action, so a live channel always accepts this send without
	// blocking under the lock. The blocking reply wait stays outside the lock.
	s.mu.Lock()
	chp := s.reqs.Load()
	if s.closed || chp == nil {
		s.mu.Unlock()
		return nil, errPassphraseCanceled
	}
	s.inflight.Store(&reply)
	*chp <- passReq{gen: int(s.gen.Load()), heading: heading, prompt: label, errMsg: errMsg, reply: reply}
	s.mu.Unlock()
	r := <-reply
	return r.pass, r.err
}

// confirmHostKey runs on the ops goroutine (from dialPush's HostKeyConfirmFn).
// It mirrors promptErr exactly for locking: the send-on-hkReqs and the
// hkInflight publish both happen under mu, so they can never race the
// close()/arm() that retire the channel. Once closed is latched (or hkReqs
// cleared) the worker abandons its send and returns errHostKeyRejected instead
// of sending on a closed channel; otherwise close cancels the published reply.
// The blocking reply wait stays outside the lock so the event loop (which the
// modal's keystrokes drive) is never starved.
func (s *passSession) confirmHostKey(host, fingerprint, keyType string) (bool, error) {
	reply := make(chan hostKeyReply, 1)
	defer s.hkInflight.Store(nil)
	s.mu.Lock()
	chp := s.hkReqs.Load()
	if s.closed || chp == nil {
		s.mu.Unlock()
		return false, errHostKeyRejected
	}
	s.hkInflight.Store(&reply)
	*chp <- hostKeyReq{gen: int(s.gen.Load()), host: host, fingerprint: fingerprint, keyType: keyType, reply: reply}
	s.mu.Unlock()
	r := <-reply
	return r.ok, r.err
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

// waitHostKeyReqCmd mirrors waitReqCmd for the host-key channel: it captures the
// current action's channel and blocks for the next host-key request. A closed
// channel (next action armed, or session close) yields !ok → nil so the reader
// retires. Within one action the channel stays open, so a host-key prompt that
// follows a passphrase prompt in the same action is delivered normally. After a
// no/yes answer the loop re-arms this reader (answerHostKey) so a single action
// can confirm more than one unknown host.
func (s *passSession) waitHostKeyReqCmd() tea.Cmd {
	ch := *s.hkReqs.Load()
	return func() tea.Msg {
		req, ok := <-ch
		if !ok {
			return nil
		}
		return hostKeyPromptMsg{req: req}
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
		m.pass.confirmHostKey,
	)
	ctx := m.ctx

	worker := func() tea.Msg {
		err := run(ctx, deps)
		bridge.done <- err
		close(bridge.events)
		return nil
	}
	return tea.Batch(worker, bridge.waitEventCmd(), bridge.waitDoneCmd(), m.pass.waitReqCmd(), m.pass.waitHostKeyReqCmd())
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
	opts := make([]string, 0, len(m.data.Groups))
	for _, g := range m.data.Groups {
		opts = append(opts, g.Name)
	}
	// With marks present the pick applies the chosen group SET to every marked
	// peer (an absolute assignment, since the targets' current groups differ).
	// The picker opens unchecked so the operator dials in the groups to apply.
	if names := m.markedNames(); len(names) > 0 {
		m.batchKind = batchEditGroups
		m.pushModal(newPickModal(fmt.Sprintf("edit groups: %d marked", len(names)), "", opts, nil))
		return m, nil
	}
	p, ok := m.selectedPeer()
	if !ok || p.Revoked {
		return m, nil
	}
	m.batchKind = batchNone
	m.pushModal(newPickModal("edit groups: "+p.Name, p.Name, opts, p.Groups))
	return m, nil
}

func (m Model) startRevoke() (tea.Model, tea.Cmd) {
	if !m.mutationsEnabled() || m.view != viewPeers {
		return m, nil
	}
	// markedNames already drops peers that are already revoked, so a batch revoke
	// never re-revokes one; an all-revoked marked set yields no targets → no-op.
	if names := m.markedNames(); len(names) > 0 {
		var live []string
		for _, n := range names {
			if p, ok := m.peerByName(n); ok && !p.Revoked {
				live = append(live, n)
			}
		}
		if len(live) == 0 {
			return m, nil
		}
		m.batchKind = batchRevoke
		m.pushModal(confirmModal{
			heading: fmt.Sprintf("revoke %d marked", len(live)),
			subject: "",
			kind:    confirmRevoke,
			body: batchConfirmBody(
				fmt.Sprintf("Clear certhold off %d peers over SSH and delete each? (Does not rotate the CA.)", len(live)), live),
		})
		return m, nil
	}
	p, ok := m.selectedPeer()
	if !ok || p.Revoked {
		return m, nil
	}
	m.batchKind = batchNone
	m.pushModal(confirmModal{
		heading: "revoke " + p.Name,
		subject: p.Name,
		kind:    confirmRevoke,
		body: []string{
			"Clear certhold off " + p.Name + " over SSH and delete its row?",
			"This does not rotate the CA.",
		},
	})
	return m, nil
}

// startRemove opens the DB-only delete confirm. Its copy deliberately contrasts
// revoke: no peer is contacted, the row is just dropped (the peer keeps any
// certhold files it already has until they expire). Supports the marked-set
// batch, mirroring startRevoke.
func (m Model) startRemove() (tea.Model, tea.Cmd) {
	if !m.mutationsEnabled() || m.view != viewPeers || m.detail {
		return m, nil
	}
	if names := m.markedNames(); len(names) > 0 {
		m.batchKind = batchRemove
		m.pushModal(confirmModal{
			heading: fmt.Sprintf("remove %d marked", len(names)),
			subject: "",
			kind:    confirmRemove,
			body: batchConfirmBody(
				fmt.Sprintf("Delete %d peer rows from the manager DB only? No peer is contacted (use revoke to clear certhold off the host).", len(names)), names),
		})
		return m, nil
	}
	p, ok := m.selectedPeer()
	if !ok {
		return m, nil
	}
	m.batchKind = batchNone
	m.pushModal(confirmModal{
		heading: "remove " + p.Name,
		subject: p.Name,
		kind:    confirmRemove,
		body: []string{
			"Delete the row for " + p.Name + " from the manager DB only.",
			"No peer is contacted — its certhold files are left in place.",
			"(Use revoke to clear certhold off the host over SSH instead.)",
		},
	})
	return m, nil
}

// startEditAddress opens a free-text prompt pre-filled with the peer's current
// address; an empty submit clears it (the manager then dials by name). DB-only.
func (m Model) startEditAddress() (tea.Model, tea.Cmd) {
	if !m.mutationsEnabled() || m.view != viewPeers || m.detail {
		return m, nil
	}
	p, ok := m.selectedPeer()
	if !ok || p.Revoked {
		return m, nil
	}
	m.pushModal(newTextModal("address "+p.Name, "address: ", p.Address, textEditAddress, p.Name))
	return m, nil
}

// startMakeClient opens the inbound->client convert confirm, offered only for
// inbound peers. For an already-client (or revoked) peer it is a no-op (no modal
// opens). MakeClient dials the peer to strip its inbound trust, so the host-key
// and passphrase prompts flow through the existing bridge.
func (m Model) startMakeClient() (tea.Model, tea.Cmd) {
	if !m.mutationsEnabled() || m.view != viewPeers || m.detail {
		return m, nil
	}
	p, ok := m.selectedPeer()
	if !ok || p.Revoked || !p.Inbound {
		return m, nil
	}
	m.batchKind = batchNone
	m.pushModal(confirmModal{
		heading: "convert " + p.Name + " to client",
		subject: p.Name,
		kind:    confirmMakeClient,
		body: []string{
			"Convert " + p.Name + " from inbound to client-style?",
			"This dials the peer to strip its inbound trust, so it stops",
			"accepting fleet inbound SSH and the manager stops dialing it.",
			"Its own outbound identity is left intact.",
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
		if hm, isHK := next.(hostKeyModal); isHK {
			return m.answerHostKey(hostKeyReply{ok: false}, hm)
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
		switch mo.kind {
		case confirmGroupDelete:
			return m.launchGroupDelete(mo.subject)
		case confirmRemove:
			if m.batchKind == batchRemove {
				return m.launchBatchRemove()
			}
			return m.launchRemove(mo.subject)
		case confirmMakeClient:
			return m.launchMakeClient(mo.subject)
		}
		if m.batchKind == batchRevoke {
			return m.launchBatchRevoke()
		}
		return m.launchRevoke(mo.subject)
	case pickModal:
		m.popModal()
		switch mo.kind {
		case pickGroupMembers:
			if m.batchKind == batchMembers {
				return m.launchBatchMembers(mo)
			}
			return m.launchMembership(mo)
		case pickPeerAllowed:
			return m.launchAllowed(mo.subject, mo.selected())
		default:
			if m.batchKind == batchEditGroups {
				return m.launchBatchEditGroups(mo.selected())
			}
			return m.launchEditGroups(mo.subject, mo.selected())
		}
	case textModal:
		m.popModal()
		return m.submitText(mo)
	case passphraseModal:
		m.popModal()
		return m.answerPassphrase(passReply{pass: []byte(mo.input.Value())}, mo)
	case hostKeyModal:
		m.popModal()
		return m.answerHostKey(hostKeyReply{ok: true}, mo)
	case rekeyModal:
		m.popModal()
		return m.submitRekey(mo)
	case enrollFormModal:
		return m.submitEnroll(mo)
	case enrollResultModal:
		m.popModal()
		return m, nil
	}
	return m, nil
}

func (m Model) launchEditGroups(name string, groups []string) (tea.Model, tea.Cmd) {
	run := func(ctx context.Context, deps ops.Deps) error {
		return ops.UpdatePeer(ctx, deps, name, groups, "")
	}
	return m.startAction("update "+name, run)
}

// launchRevoke runs the default clear+delete revoke path (rekey=false). A TUI
// affordance for --rekey / DB-only remove is a follow-up (out of T142 scope).
func (m Model) launchRevoke(name string) (tea.Model, tea.Cmd) {
	hostname := m.action.Hostname
	run := func(ctx context.Context, deps ops.Deps) error {
		return ops.RevokePeer(ctx, deps, name, hostname, false)
	}
	return m.startAction("revoke "+name, run)
}

// launchRemove runs the DB-only delete (no peer contact), contrasting
// launchRevoke which clears certhold off the host first.
func (m Model) launchRemove(name string) (tea.Model, tea.Cmd) {
	run := func(ctx context.Context, deps ops.Deps) error {
		return ops.RemovePeer(ctx, deps, name)
	}
	return m.startAction("remove "+name, run)
}

// launchMakeClient converts an inbound peer to client-style; the dial may raise
// host-key/passphrase prompts, handled by the existing bridge.
func (m Model) launchMakeClient(name string) (tea.Model, tea.Cmd) {
	hostname := m.action.Hostname
	run := func(ctx context.Context, deps ops.Deps) error {
		return ops.MakeClient(ctx, deps, name, hostname)
	}
	return m.startAction("convert "+name, run)
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
	if msg.req.errMsg != "" {
		pm.errMsg = msg.req.errMsg
	}
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

// handleHostKeyPrompt opens the host-key modal for a confirm request raised by
// the ops dial and remembers the reply channel. A stale request (gen mismatch,
// e.g. a superseded action's dial) is rejected so the orphaned worker unblocks.
func (m Model) handleHostKeyPrompt(msg hostKeyPromptMsg) (tea.Model, tea.Cmd) {
	if msg.req.gen != m.actionGen {
		msg.req.reply <- hostKeyReply{err: errHostKeyRejected}
		return m, nil
	}
	hm := newHostKeyModal(msg.req.host, msg.req.fingerprint, msg.req.keyType)
	hm.reply = msg.req.reply
	// The host-key modal sits above the (already-pushed) progress modal so a
	// yes/no feeds the blocked worker; on dismissal answerHostKey rejects the
	// dial and the progress modal renders the cancellation.
	m.pushModal(hm)
	return m, nil
}

// answerHostKey feeds the worker's reply channel. Unlike answerPassphrase a no
// is a normal reject (the dial fails, no whole-action retry). After answering we
// re-arm the host-key reader so a single action can confirm more than one
// unknown host before it completes.
func (m Model) answerHostKey(r hostKeyReply, hm hostKeyModal) (tea.Model, tea.Cmd) {
	if hm.reply != nil {
		hm.reply <- r
	}
	return m, m.pass.waitHostKeyReqCmd()
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
		answerDiscardedHostKeys(m.modals[idx:])
		m.modals = m.modals[:idx]
		m.passErr = msg.err.Error()
		return m.startAction(m.lastHeading, m.lastRun)
	}
	answerDiscardedHostKeys(m.modals[idx+1:])
	m.modals = m.modals[:idx+1] // discard any modal stranded above the progress
	// A successful mint swaps the progress modal for the result screen showing
	// the one-liner full-width; the enroll worker stashed the result in the
	// shared holder. A failed mint falls through to the normal done/err modal.
	if m.enrollPending {
		pending := m.enrollPending
		m.enrollPending = false
		if msg.err == nil && pending {
			if res := m.enrollResult.Load(); res != nil {
				m.modals[idx] = newEnrollResultModal(*res, m.enrollClient)
				return m, m.reloadCmd()
			}
		}
	}
	// A fully-completed batch clears marks on the peers it touched, keeping only
	// the failed ones marked for a retry. A canceled passphrase (the run never
	// reached its outcome store) leaves every mark intact. The outcome holder is
	// written exactly once by the worker before it returns its terminal error.
	if m.batchOutcome != nil {
		if out := m.batchOutcome.Load(); out != nil {
			failed := map[string]bool{}
			for _, n := range out.failed {
				failed[n] = true
			}
			for n := range m.marks {
				if !failed[n] {
					delete(m.marks, n)
				}
			}
			if len(m.marks) == 0 {
				m.marks = nil
			}
		}
		m.batchOutcome = nil
		m.batchKind = batchNone
	}
	pm := m.modals[idx].(progressModal)
	pm.done = true
	pm.err = msg.err
	m.modals[idx] = pm
	return m, m.reloadCmd()
}

// answerDiscardedHostKeys rejects the reply channel of every host-key modal in
// a slice of modals about to be discarded. The confirm that raised such a modal
// runs on the SSH handshake goroutine, which outlives the action's worker when
// the dial is abandoned — so the done message can arrive with the modal still
// open, and dropping it unanswered would park that goroutine forever. The send
// is non-blocking: the channel is buffered (cap 1) and answered at most once.
func answerDiscardedHostKeys(discarded []modal) {
	for _, mo := range discarded {
		hm, ok := mo.(hostKeyModal)
		if !ok || hm.reply == nil {
			continue
		}
		select {
		case hm.reply <- hostKeyReply{err: errHostKeyRejected}:
		default:
		}
	}
}

func (m Model) progressIndex() int {
	for i := len(m.modals) - 1; i >= 0; i-- {
		if _, ok := m.modals[i].(progressModal); ok {
			return i
		}
	}
	return -1
}
