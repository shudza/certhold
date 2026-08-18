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
// rekey == true: flags the row revoked, runs a partial CA rotation that
// re-signs and pushes to every remaining peer, and hard-deletes the row only
// once the rotation succeeded. The revoked host is never contacted, so this is
// the path for a compromised or unreachable peer. hostname is certhold's own
// peer name; empty resolves via the persisted self name (then os.Hostname()).
func RevokePeer(ctx context.Context, deps Deps, name, hostname string, rekey bool) error {
	if err := guardNotSelfPeer(ctx, deps.DB, "revoke", name, hostname); err != nil {
		return err
	}
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

// revokeClear is the default path: clear certhold off the reachable peer,
// delete its row, and bump fleet_rev so other peers refresh on their next pull
// and drop the revoked peer's Host alias.
func revokeClear(ctx context.Context, deps Deps, peer *db.Peer) error {
	name := peer.Name
	if !peer.Inbound {
		return fmt.Errorf("peer %q is a no-inbound/client peer and cannot be cleared over SSH; use `certhold remove %s` (DB-only) or `certhold revoke --rekey %s` (rotate the CA)", name, name, name)
	}

	caPubs, err := instanceCAPubKeys(deps, name)
	if err != nil {
		return err
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
	if err := pusher.ClearPeer(ctx, paths, instanceKey, caPubs); err != nil {
		err = fmt.Errorf("clear peer %s: %w; peer NOT deleted — use `certhold remove %s` or `certhold revoke --rekey %s`", name, err, name, name)
		deps.emit(Event{Type: EventPeerFailed, Peer: name, Err: err})
		return err
	}

	if err := deps.DB.DeletePeer(ctx, name); err != nil {
		return fmt.Errorf("delete peer %q: %w", name, err)
	}
	if err := deps.DB.BumpFleetRev(ctx); err != nil {
		return fmt.Errorf("bump fleet_rev: %w", err)
	}
	deps.emit(Event{Type: EventPeerDone, Peer: name, Msg: fmt.Sprintf("cleared and removed %s", name)})
	deps.info(name, fmt.Sprintf("Revoked %s: certhold stripped from the peer and its row deleted.", name))
	return nil
}

// revokeRekey is the --rekey path: flag the row revoked first — the Rekey loop
// skips revoked peers and ReachableHosts filters them out, so the rotation and
// every config it pushes exclude the peer — then rotate the CA across the
// remaining fleet, and hard-delete the row only once the rotation succeeded.
// The revoked host is never contacted.
//
// Flag-then-rotate keeps a failed rotation recoverable: if Rekey fails at a
// precondition (wrong CA passphrase, leftover ca.next) nothing was rotated, the
// manager still authenticates to the whole fleet with its current cert, and the
// flagged row keeps the peer visible in `list` — its old cert is still valid,
// so silently losing the row would read as success. A retried `revoke --rekey`
// converges: GetPeer and SetPeerRevoked both accept an already-revoked row. On
// Rekey success the manager re-signed its own files against the new CA and
// every remaining reachable peer trusts it, so deleting the row last changes
// nothing about who can authenticate.
func revokeRekey(ctx context.Context, deps Deps, name, hostname string) error {
	hostname, err := resolveSelfName(ctx, deps.DB, hostname)
	if err != nil {
		return err
	}

	if err := deps.DB.SetPeerRevoked(ctx, name); err != nil {
		return fmt.Errorf("flag peer %q revoked: %w", name, err)
	}

	if err := Rekey(ctx, deps, RekeyOptions{Hostname: hostname}); err != nil {
		return fmt.Errorf("rekey-revoke: %w; %s is now flagged revoked and excluded from pushed configs, but the CA was NOT rotated: its old cert is STILL VALID fleet-wide until a rekey succeeds — re-run `certhold revoke --rekey %s`", err, name, name)
	}

	if err := deps.DB.DeletePeer(ctx, name); err != nil {
		return fmt.Errorf("delete peer %q: %w; the CA was rotated so its old cert is no longer accepted, but its revoked row remains — clean it up with `certhold remove %s`", name, err, name)
	}
	deps.info(name, fmt.Sprintf("Revoked %s via CA rekey; its row was deleted.", name))
	return nil
}

// instanceCAPubKeys returns every CA public key this instance has ever used:
// the active CA's key plus the key of each archived old CA under
// dataDir/ca.old.*. Revoke strips all of them off the peer, so a straggler that
// missed a past rekey does not keep a stale old-CA cert-authority line behind a
// clean-looking clear. Only the active key is required; an archive whose ca.pub
// is missing or unreadable just warns, so a damaged archive cannot block a
// revoke.
func instanceCAPubKeys(deps Deps, peerName string) ([]ssh.PublicKey, error) {
	caPubBytes, err := ca.LoadPublicKey(filepath.Join(deps.DataDir, "ca"))
	if err != nil {
		return nil, fmt.Errorf("load ca public key: %w", err)
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey(caPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca public key: %w", err)
	}
	keys := []ssh.PublicKey{caPub}

	// Glob only errors on a malformed pattern; this one is fixed.
	archives, _ := filepath.Glob(filepath.Join(deps.DataDir, "ca.old.*"))
	for _, dir := range archives {
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			continue
		}
		oldPubBytes, err := ca.LoadPublicKey(dir)
		if err != nil {
			deps.warn(peerName, fmt.Sprintf("revoke: cannot load archived CA public key from %s: %v; a cert-authority line for that CA may remain on the peer", dir, err))
			continue
		}
		oldPub, _, _, _, err := ssh.ParseAuthorizedKey(oldPubBytes)
		if err != nil {
			deps.warn(peerName, fmt.Sprintf("revoke: cannot parse archived CA public key from %s: %v; a cert-authority line for that CA may remain on the peer", dir, err))
			continue
		}
		keys = append(keys, oldPub)
	}
	return keys, nil
}
