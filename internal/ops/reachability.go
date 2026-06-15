package ops

import (
	"context"
	"fmt"
	"time"

	"github.com/shudza/certhold/internal/db"
)

// SelfFetchNoticeMsg is the operator notice that a peer was not dialed because
// the manager cannot reach it (push_reachable=0). Its DB-side changes land on
// its next `certhold-cli refresh`, exactly like a client-style peer.
func SelfFetchNoticeMsg(name string) string {
	return fmt.Sprintf("peer %s: push-unreachable; changes pending until 'certhold-cli refresh' runs on it", name)
}

// skipPushNotice reports whether a push path must skip dialing a peer and route
// it onto the self-fetch (pull) channel instead, plus the operator notice to
// emit. A client-style peer (no inbound) is skipped as before; a
// push-unreachable peer (the manager cannot dial it back) is skipped the same
// way so a command does not fail with `knownhosts: key is unknown` /
// `dial tcp` against a peer it can never reach.
func skipPushNotice(p *db.Peer) (bool, string) {
	if !p.Inbound {
		return true, ClientPeerNoticeMsg(p.Name)
	}
	if !p.PushReachable {
		return true, SelfFetchNoticeMsg(p.Name)
	}
	return false, ""
}

// ProbeAndCaptureHostKey performs an outbound SSH dial to the peer with
// enroll-time host-key capture enabled: a successful dial (a) confirms the
// manager can reach the peer for pushes and (b) records the peer's host key in
// the manager's known_hosts so later strict pushes verify. It updates
// peers.push_reachable accordingly and never returns the dial error as fatal —
// an unreachable peer is a normal, expected outcome (non-bidirectional peer),
// not an enrollment failure. The returned bool is the reachability verdict.
func ProbeAndCaptureHostKey(ctx context.Context, deps Deps, peerName, host, targetUser string) (bool, error) {
	self := resolveSelfIdent(ctx, deps.DB)
	pushOpts := SelfPushOptions(deps.DataDir, self, deps.PeerPass)
	pushOpts.User = targetUser
	if pushOpts.User == "" {
		pushOpts.User = "root"
	}
	pushOpts.CaptureHostKey = true

	// The dial keeps the caller's (timeout-bound) ctx — it is what should be
	// cancelled when the probe gives up on a slow/unreachable peer.
	pusher, dialErr := deps.Dial(ctx, host, pushOpts)
	reachable := dialErr == nil
	// Only close a pusher from a SUCCESSFUL dial. A failed sshpush.Dial returns a
	// typed-nil *Client as a non-nil Pusher interface, so a `pusher != nil` guard
	// is not enough — closing it would dereference the nil *Client.
	if reachable && pusher != nil {
		_ = pusher.Close()
	}

	// Record the verdict on a context created AFTER the dial and detached from
	// it: an unreachable dial can burn (or exceed) the caller's whole deadline,
	// so a write context that spanned the dial — or reused the caller ctx —
	// would already be expired, fail with "context deadline exceeded", and
	// silently leave the peer at its default push_reachable=1. WithoutCancel
	// keeps any request values while dropping the (possibly tripped) deadline.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := deps.DB.SetPeerReachable(writeCtx, peerName, reachable); err != nil {
		return reachable, fmt.Errorf("set peer reachable: %w", err)
	}
	return reachable, dialErr
}
