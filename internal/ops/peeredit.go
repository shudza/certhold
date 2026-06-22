package ops

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/peerfiles"
)

// SetPeerAddress records the network address the manager dials to reach this
// peer (empty clears it, so the manager dials by name). This is a DB-only
// mutation: no peer is contacted. fleet_rev is bumped so other peers refresh
// their Host-alias entries on their next pull — a full fleet re-push is not
// required.
func SetPeerAddress(ctx context.Context, deps Deps, name, address string) error {
	if _, err := deps.DB.GetPeer(ctx, name); err != nil {
		if errors.Is(err, db.ErrPeerNotFound) {
			return fmt.Errorf("peer %q not found", name)
		}
		return fmt.Errorf("get peer: %w", err)
	}

	if err := deps.DB.SetPeerAddress(ctx, name, address); err != nil {
		return fmt.Errorf("set peer address: %w", err)
	}
	if err := deps.DB.BumpFleetRev(ctx); err != nil {
		return fmt.Errorf("bump fleet_rev: %w", err)
	}

	if address == "" {
		deps.info(name, fmt.Sprintf("peer %s address cleared; manager will dial by name", name))
	} else {
		deps.info(name, fmt.Sprintf("peer %s address set to %s", name, address))
	}
	return nil
}

// MakeClient converts an inbound peer into a client-style peer (one-way:
// inbound -> client). While the peer is still reachable it is dialed and its
// ~/.ssh/authorized_keys is rewritten with the CA cert-authority line removed,
// so it stops accepting fleet inbound SSH; its own identity/config is left
// intact so outbound keeps working. Only on a successful push is inbound set
// false and fleet_rev bumped — a dial/push failure returns the error and leaves
// the peer marked inbound (it still accepts inbound, so the DB must reflect
// that). An already-client peer is a clear no-op. hostname anchors the manager's
// self-push identity (its own peer name).
func MakeClient(ctx context.Context, deps Deps, name, hostname string) error {
	peer, err := deps.DB.GetPeer(ctx, name)
	if err != nil {
		if errors.Is(err, db.ErrPeerNotFound) {
			return fmt.Errorf("peer %q not found", name)
		}
		return fmt.Errorf("get peer: %w", err)
	}
	if !peer.Inbound {
		deps.info(name, fmt.Sprintf("peer %s is already a client (accepts no inbound); nothing to do", name))
		return nil
	}
	if !peer.PushReachable {
		return fmt.Errorf("peer %s is push-unreachable: cannot strip its inbound trust; re-enroll it as --client instead", name)
	}

	host := peer.DialHost()

	pushOpts := SelfPushOptions(deps.DataDir, SelfIdentFor(ctx, deps.DB, hostname), deps.PeerPass)
	pushOpts.User = pushUser(peer)
	deps.emit(Event{Type: EventPeerStart, Peer: name})
	pusher, err := dialPush(ctx, deps, host, pushOpts)
	if err != nil {
		err = fmt.Errorf("ssh dial %s: %w", host, err)
		deps.emit(Event{Type: EventPeerFailed, Peer: name, Err: err})
		return err
	}
	defer pusher.Close()

	fail := func(err error) error {
		deps.emit(Event{Type: EventPeerFailed, Peer: name, Err: err})
		return err
	}

	caPub, err := loadCAPublicKey(deps.DataDir)
	if err != nil {
		return fail(err)
	}
	remote := PeerAuthorizedKeysRemotePath(peer)
	existing, err := pusher.ReadFile(ctx, remote)
	if err != nil {
		return fail(fmt.Errorf("read %s: %w", remote, err))
	}
	stripped := peerfiles.StripCALine(existing, caPub)
	if err := pusher.WriteFileAtomic(ctx, remote, stripped, fs.FileMode(0644)); err != nil {
		return fail(fmt.Errorf("write %s: %w", remote, err))
	}
	if err := pusher.VerifyHealth(ctx); err != nil {
		return fail(fmt.Errorf("verify health: %w", err))
	}

	if err := deps.DB.SetPeerInbound(ctx, name, false); err != nil {
		return fail(fmt.Errorf("set peer inbound: %w", err))
	}
	if err := deps.DB.BumpFleetRev(ctx); err != nil {
		return fail(fmt.Errorf("bump fleet_rev: %w", err))
	}

	deps.emit(Event{Type: EventPeerDone, Peer: name, Msg: fmt.Sprintf("peer %s converted to client; it no longer accepts fleet inbound SSH", name)})
	return nil
}
