package ops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/peerfiles"
)

// RevokePeer removes a peer from the fleet. It has two modes.
//
// Default (rekey == false): a clean decommission of a reachable, inbound peer.
// The manager SSHes into the peer and strips certhold (config block, identity
// files, and the cert-authority trust line) via ClearPeer, then hard-deletes
// the peer's DB row. A no-inbound/client peer is never dialed, so it is rejected
// up front with guidance to use `remove` or `revoke --rekey`; the row is left
// intact. A dial/clear failure (e.g. an unreachable host) returns the error
// without deleting, with the same guidance.
//
// rekey == true: a partial CA rotation that re-signs and pushes to every
// remaining peer, then hard-deletes the revoked row. The revoked host is never
// contacted, so this is the path for a compromised or unreachable peer. hostname
// is certhold's own peer name; empty means os.Hostname().
func RevokePeer(ctx context.Context, deps Deps, name, hostname string, rekey bool) error {
	peer, err := deps.DB.GetPeer(ctx, name)
	if err != nil {
		if errors.Is(err, db.ErrPeerNotFound) {
			return fmt.Errorf("revoke peer %q: %w", name, err)
		}
		return fmt.Errorf("get peer %q: %w", name, err)
	}

	if rekey {
		return revokeRekey(ctx, deps, name, hostname)
	}
	return revokeClear(ctx, deps, peer)
}

// revokeClear is the default path: clear certhold off the reachable peer, then
// delete its row.
func revokeClear(ctx context.Context, deps Deps, peer *db.Peer) error {
	name := peer.Name
	if !peer.Inbound {
		return fmt.Errorf("peer %q is a no-inbound/client peer and cannot be cleared over SSH; use `certhold remove %s` (DB-only) or `certhold revoke --rekey %s` (rotate the CA)", name, name, name)
	}

	caDir := filepath.Join(deps.DataDir, "ca")
	caPubBytes, err := ca.LoadPublicKey(caDir)
	if err != nil {
		return fmt.Errorf("load ca public key: %w", err)
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey(caPubBytes)
	if err != nil {
		return fmt.Errorf("parse ca public key: %w", err)
	}

	instanceKey, err := EnsureInstanceKey(ctx, deps.DB)
	if err != nil {
		return fmt.Errorf("ensure instance key: %w", err)
	}

	pushOpts := SelfPushOptions(deps.DataDir, resolveSelfIdent(ctx, deps.DB), deps.PeerPass)
	pushOpts.User = pushUser(peer)

	deps.emit(Event{Type: EventPeerStart, Peer: name})
	host := peer.DialHost()
	pusher, err := dialPush(ctx, deps, host, pushOpts)
	if err != nil {
		err = fmt.Errorf("ssh dial %s: %w; peer not cleared and NOT deleted — use `certhold remove %s` or `certhold revoke --rekey %s`", host, err, name, name)
		deps.emit(Event{Type: EventPeerFailed, Peer: name, Err: err})
		return err
	}
	defer pusher.Close()

	paths := peerfiles.PathsFor(peer.TargetUser, instanceKey)
	if err := pusher.ClearPeer(ctx, paths, instanceKey, caPub); err != nil {
		err = fmt.Errorf("clear peer %s: %w; peer NOT deleted — use `certhold remove %s` or `certhold revoke --rekey %s`", name, err, name, name)
		deps.emit(Event{Type: EventPeerFailed, Peer: name, Err: err})
		return err
	}

	if err := deps.DB.DeletePeer(ctx, name); err != nil {
		return fmt.Errorf("delete peer %q: %w", name, err)
	}
	deps.emit(Event{Type: EventPeerDone, Peer: name, Msg: fmt.Sprintf("cleared and removed %s", name)})
	deps.info(name, fmt.Sprintf("Revoked %s: certhold stripped from the peer and its row deleted.", name))
	return nil
}

// revokeRekey is the --rekey path: delete the revoked row first so the rotation
// naturally excludes it, then rotate the CA across the remaining fleet. The
// revoked host is never contacted. Deleting before rotating keeps the
// trust-root-lockout reasoning intact: the manager re-signs its own files last
// against the new CA, and every remaining (reachable) peer is rotated to trust
// it, so the manager can still authenticate to the fleet afterwards.
func revokeRekey(ctx context.Context, deps Deps, name, hostname string) error {
	if hostname == "" {
		h, herr := os.Hostname()
		if herr != nil {
			return fmt.Errorf("hostname: %w", herr)
		}
		hostname = h
	}

	if err := deps.DB.DeletePeer(ctx, name); err != nil {
		return fmt.Errorf("delete peer %q: %w", name, err)
	}

	if err := Rekey(ctx, deps, RekeyOptions{Hostname: hostname}); err != nil {
		return fmt.Errorf("rekey-revoke: %w", err)
	}
	deps.info(name, fmt.Sprintf("Revoked %s via CA rekey; its row was deleted.", name))
	return nil
}
