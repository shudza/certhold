package ops

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
)

// UpdatePeer reissues a peer's cert with new groups (sign → db SetPeerGroups/
// SetPeerCert → BumpFleetRev → push to inbound peer). host overrides the dial
// target; empty means the peer's DialHost(). hostname is certhold's own peer
// name when the caller has one; empty resolves via the persisted self name
// (then os.Hostname() for pre-feature state). The manager's
// own peer row is refused: its groups are meaningless (the manager reaches the
// whole fleet through the manager principal, which lives on its cert and not in
// the group table) and re-signing it here would strip that principal. `rekey`
// is the sanctioned path that re-issues the self cert.
func UpdatePeer(ctx context.Context, deps Deps, name string, groups []string, host, hostname string) error {
	if err := guardNotSelfPeer(ctx, deps.DB, "edit the groups of", name, hostname); err != nil {
		return err
	}

	caObj, err := ca.LoadWithPassphrase(filepath.Join(deps.DataDir, "ca"), deps.CAUnlock)
	if err != nil {
		return fmt.Errorf("load ca: %w", err)
	}

	peer, err := deps.DB.GetPeer(ctx, name)
	if err != nil {
		if errors.Is(err, db.ErrPeerNotFound) {
			return fmt.Errorf("peer %q not found", name)
		}
		return fmt.Errorf("get peer: %w", err)
	}
	if peer.Revoked {
		return fmt.Errorf("peer %q is revoked", name)
	}
	if host == "" {
		host = peer.DialHost()
	}

	pk, _, _, _, err := ssh.ParseAuthorizedKey(peer.AuthorizedKey)
	if err != nil {
		return fmt.Errorf("parse peer pubkey: %w", err)
	}

	principals := certPrincipals(name, groups, false)
	certBytes, serial, err := caObj.SignCert(ca.SignOptions{
		Pubkey:     pk,
		KeyID:      name,
		Principals: principals,
	})
	if err != nil {
		return fmt.Errorf("sign cert: %w", err)
	}

	for _, g := range groups {
		exists, err := deps.DB.GroupExists(ctx, g)
		if err != nil {
			return fmt.Errorf("check group %q: %w", g, err)
		}
		if !exists {
			return fmt.Errorf("group %q does not exist (run \"certhold group create %s\" first)", g, g)
		}
	}
	if err := deps.DB.SetPeerGroups(ctx, name, groups); err != nil {
		return fmt.Errorf("set peer groups: %w", err)
	}
	if err := deps.DB.SetPeerCert(ctx, name, certBytes, serial); err != nil {
		return fmt.Errorf("set peer cert: %w", err)
	}

	instanceKey, err := EnsureInstanceKey(ctx, deps.DB)
	if err != nil {
		return fmt.Errorf("ensure instance key: %w", err)
	}

	if err := deps.DB.BumpFleetRev(ctx); err != nil {
		return fmt.Errorf("bump fleet_rev: %w", err)
	}

	if skip, notice := skipPushNotice(peer); skip {
		deps.info(name, notice)
		deps.emit(Event{Type: EventPeerDone, Peer: name, Msg: fmt.Sprintf("updated %s (serial %d)", name, serial)})
		return nil
	}

	deps.emit(Event{Type: EventPeerStart, Peer: name})

	pushOpts := SelfPushOptions(deps.DataDir, resolveSelfIdent(ctx, deps.DB), deps.PeerPass)
	pushOpts.User = pushUser(peer)
	pusher, err := dialPush(ctx, deps, host, pushOpts)
	if err != nil {
		err = fmt.Errorf("ssh dial %s: %w", host, err)
		deps.emit(Event{Type: EventPeerFailed, Peer: name, Err: err})
		return err
	}
	defer pusher.Close()

	certPath := PeerCertRemotePath(peer, instanceKey)
	if err := pusher.WriteFileAtomic(ctx, certPath, certBytes, 0644); err != nil {
		err = fmt.Errorf("write cert: %w", err)
		deps.emit(Event{Type: EventPeerFailed, Peer: name, Err: err})
		return err
	}
	if err := SplicePeerConfig(ctx, pusher, deps.DB, peer, instanceKey); err != nil {
		err = fmt.Errorf("splice ssh config: %w", err)
		deps.emit(Event{Type: EventPeerFailed, Peer: name, Err: err})
		return err
	}
	if err := pusher.VerifyHealth(ctx); err != nil {
		err = fmt.Errorf("verify health: %w", err)
		deps.emit(Event{Type: EventPeerFailed, Peer: name, Err: err})
		return err
	}

	deps.emit(Event{Type: EventPeerDone, Peer: name, Msg: fmt.Sprintf("updated %s (serial %d)", name, serial)})
	return nil
}
