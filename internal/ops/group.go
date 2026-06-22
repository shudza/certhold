package ops

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/peerfiles"
)

// GroupCreate creates a new group and bumps the fleet revision. The summary
// line is emitted as an EventInfo.
func GroupCreate(ctx context.Context, deps Deps, name string) error {
	if name == peerfiles.ManagerPrincipal {
		return fmt.Errorf("group %q is reserved", name)
	}
	if err := deps.DB.CreateGroup(ctx, name); err != nil {
		switch {
		case errors.Is(err, db.ErrGroupExists):
			return fmt.Errorf("group %q already exists", name)
		case errors.Is(err, db.ErrInvalidGroupName):
			return fmt.Errorf("invalid group name %q", name)
		default:
			return fmt.Errorf("create group: %w", err)
		}
	}
	if err := deps.DB.BumpFleetRev(ctx); err != nil {
		return fmt.Errorf("bump fleet_rev: %w", err)
	}
	deps.info("", fmt.Sprintf("group %q created", name))
	return nil
}

// GroupRename renames a group and pushes the cascading rewrite to every
// affected peer: members get a re-signed cert, allowing peers get their
// authorized_keys principals rewritten. hostname is certhold's own peer name
// anchoring the self push identity. Per-peer progress is emitted as
// EventPeerStart/EventPeerDone/EventPeerFailed (Done carries no Msg: the CLI
// historically printed nothing per peer).
func GroupRename(ctx context.Context, deps Deps, oldName, newName, hostname string) error {
	newName = strings.TrimSpace(newName)
	if oldName == peerfiles.ManagerPrincipal || newName == peerfiles.ManagerPrincipal {
		return fmt.Errorf("group %q is reserved", peerfiles.ManagerPrincipal)
	}

	if oldName == newName {
		exists, err := deps.DB.GroupExists(ctx, oldName)
		if err != nil {
			return fmt.Errorf("group exists: %w", err)
		}
		if !exists {
			return fmt.Errorf("group %q does not exist", oldName)
		}
		deps.info("", fmt.Sprintf("group %q renamed (no change)", oldName))
		return nil
	}

	casc, err := loadGroupCascade(ctx, deps.DB, oldName)
	if err != nil {
		return err
	}

	if err := deps.DB.RenameGroup(ctx, oldName, newName); err != nil {
		switch {
		case errors.Is(err, db.ErrGroupNotFound):
			return fmt.Errorf("group %q does not exist", oldName)
		case errors.Is(err, db.ErrGroupExists):
			return fmt.Errorf("group %q already exists", newName)
		case errors.Is(err, db.ErrInvalidGroupName):
			return fmt.Errorf("invalid group name %q", newName)
		default:
			return fmt.Errorf("rename group: %w", err)
		}
	}
	if err := deps.DB.BumpFleetRev(ctx); err != nil {
		return fmt.Errorf("bump fleet_rev: %w", err)
	}

	if len(casc.affected) == 0 {
		deps.info("", fmt.Sprintf("group renamed: %q → %q (no peers affected)", oldName, newName))
		return nil
	}

	var caObj *ca.CA
	if len(casc.members) > 0 {
		caObj, err = ca.LoadWithPassphrase(filepath.Join(deps.DataDir, "ca"), deps.CAUnlock)
		if err != nil {
			return fmt.Errorf("load ca: %w", err)
		}
	}

	caPub, err := loadCAPublicKey(deps.DataDir)
	if err != nil {
		return err
	}

	instanceKey, err := EnsureInstanceKey(ctx, deps.DB)
	if err != nil {
		return fmt.Errorf("ensure instance key: %w", err)
	}

	self := SelfIdentFor(ctx, deps.DB, hostname)
	var stragglers []string
	var touched []string

	for _, peerName := range casc.affected {
		peer, err := deps.DB.GetPeer(ctx, peerName)
		if err != nil {
			if errors.Is(err, db.ErrPeerNotFound) {
				continue
			}
			return fmt.Errorf("get peer %q: %w", peerName, err)
		}
		if peer.Revoked {
			continue
		}

		_, isMember := casc.memberSet[peerName]
		_, isAllow := casc.allowedBySet[peerName]

		var certBytes []byte
		if isMember {
			currentGroups, err := deps.DB.GetPeerGroups(ctx, peerName)
			if err != nil {
				return fmt.Errorf("get peer groups %q: %w", peerName, err)
			}
			certBytes, err = signAndStorePeerCert(ctx, deps.DB, caObj, peer, currentGroups)
			if err != nil {
				return err
			}
		}

		var currentAllowed []string
		if isAllow {
			currentAllowed, err = deps.DB.GetPeerAllowedGroups(ctx, peerName)
			if err != nil {
				return fmt.Errorf("get peer allowed groups %q: %w", peerName, err)
			}
		}

		if skip, notice := skipPushNotice(peer); skip {
			deps.info(peerName, notice)
			continue
		}

		deps.emit(Event{Type: EventPeerStart, Peer: peerName})
		if err := pushGroupCascade(ctx, deps, self, peer, instanceKey, caPub, isMember, certBytes, isAllow, currentAllowed, true); err != nil {
			stragglers = append(stragglers, peerName)
			deps.emit(Event{Type: EventPeerFailed, Peer: peerName, Err: err})
			continue
		}
		touched = append(touched, peerName)
		deps.emit(Event{Type: EventPeerDone, Peer: peerName})
	}

	if len(stragglers) > 0 {
		deps.warn("", fmt.Sprintf("peers with unfinished pushes (DB rename already committed): %s", strings.Join(stragglers, ",")))
		return fmt.Errorf("group rename incomplete: %d straggler(s)", len(stragglers))
	}

	deps.info("", fmt.Sprintf("group renamed: %q → %q (peers updated: %s)", oldName, newName, strings.Join(touched, ",")))
	return nil
}

// GroupDelete deletes a group and pushes the cascading removal to every
// affected peer (member certs re-signed without the group, allowing peers'
// authorized_keys principals rewritten). The group row is only deleted once
// every affected peer was pushed; stragglers keep it. hostname is certhold's
// own peer name anchoring the self push identity.
func GroupDelete(ctx context.Context, deps Deps, name, hostname string) error {
	if name == peerfiles.ManagerPrincipal {
		return fmt.Errorf("group %q is reserved", name)
	}

	exists, err := deps.DB.GroupExists(ctx, name)
	if err != nil {
		return fmt.Errorf("group exists: %w", err)
	}
	if !exists {
		return fmt.Errorf("group %q does not exist", name)
	}

	casc, err := loadGroupCascade(ctx, deps.DB, name)
	if err != nil {
		return err
	}

	if len(casc.affected) == 0 {
		if err := deps.DB.DeleteGroup(ctx, name); err != nil {
			return fmt.Errorf("delete group: %w", err)
		}
		if err := deps.DB.BumpFleetRev(ctx); err != nil {
			return fmt.Errorf("bump fleet_rev: %w", err)
		}
		deps.info("", fmt.Sprintf("group %q deleted (no peers affected)", name))
		return nil
	}

	var caObj *ca.CA
	if len(casc.members) > 0 {
		caObj, err = ca.LoadWithPassphrase(filepath.Join(deps.DataDir, "ca"), deps.CAUnlock)
		if err != nil {
			return fmt.Errorf("load ca: %w", err)
		}
	}

	caPub, err := loadCAPublicKey(deps.DataDir)
	if err != nil {
		return err
	}

	instanceKey, err := EnsureInstanceKey(ctx, deps.DB)
	if err != nil {
		return fmt.Errorf("ensure instance key: %w", err)
	}

	self := SelfIdentFor(ctx, deps.DB, hostname)
	var stragglers []string
	var touched []string

	for _, peerName := range casc.affected {
		peer, err := deps.DB.GetPeer(ctx, peerName)
		if err != nil {
			if errors.Is(err, db.ErrPeerNotFound) {
				continue
			}
			return fmt.Errorf("get peer %q: %w", peerName, err)
		}
		if peer.Revoked {
			continue
		}

		_, isMember := casc.memberSet[peerName]
		_, isAllow := casc.allowedBySet[peerName]

		var certBytes []byte
		if isMember {
			currentGroups, err := deps.DB.GetPeerGroups(ctx, peerName)
			if err != nil {
				return fmt.Errorf("get peer groups %q: %w", peerName, err)
			}
			newGroups := removeStr(currentGroups, name)
			certBytes, err = signAndStorePeerCert(ctx, deps.DB, caObj, peer, newGroups)
			if err != nil {
				return err
			}
			if err := deps.DB.SetPeerGroups(ctx, peerName, newGroups); err != nil {
				return fmt.Errorf("set peer groups %q: %w", peerName, err)
			}
		}

		var newAllowed []string
		if isAllow {
			currentAllowed, err := deps.DB.GetPeerAllowedGroups(ctx, peerName)
			if err != nil {
				return fmt.Errorf("get peer allowed groups %q: %w", peerName, err)
			}
			newAllowed = removeStr(currentAllowed, name)
			if err := deps.DB.SetPeerAllowedGroups(ctx, peerName, newAllowed); err != nil {
				return fmt.Errorf("set peer allowed groups %q: %w", peerName, err)
			}
		}

		if skip, notice := skipPushNotice(peer); skip {
			deps.info(peerName, notice)
			continue
		}

		deps.emit(Event{Type: EventPeerStart, Peer: peerName})
		if err := pushGroupCascade(ctx, deps, self, peer, instanceKey, caPub, isMember, certBytes, isAllow, newAllowed, false); err != nil {
			stragglers = append(stragglers, peerName)
			deps.emit(Event{Type: EventPeerFailed, Peer: peerName, Err: err})
			continue
		}
		touched = append(touched, peerName)
		deps.emit(Event{Type: EventPeerDone, Peer: peerName})
	}

	if len(stragglers) > 0 {
		deps.warn("", fmt.Sprintf("peers with unfinished pushes (DB not deleted): %s", strings.Join(stragglers, ",")))
		return fmt.Errorf("group delete incomplete: %d straggler(s)", len(stragglers))
	}

	if err := deps.DB.DeleteGroup(ctx, name); err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	if err := deps.DB.BumpFleetRev(ctx); err != nil {
		return fmt.Errorf("bump fleet_rev: %w", err)
	}
	deps.info("", fmt.Sprintf("group %q deleted; affected peers: %s", name, strings.Join(touched, ",")))
	return nil
}

// SetPeerAllowedGroups replaces a peer's allowed-groups list: db rows + fleet
// rev, then (for inbound peers) the authorized_keys principals rewrite and
// config splice pushed over SSH. host overrides the dial target; empty means
// the peer's DialHost(). hostname is certhold's own peer name anchoring the
// self push identity. Client-style peers get the pending-refresh notice and no
// dial.
func SetPeerAllowedGroups(ctx context.Context, deps Deps, peerName string, groups []string, host, hostname string) error {
	peer, err := deps.DB.GetPeer(ctx, peerName)
	if err != nil {
		if errors.Is(err, db.ErrPeerNotFound) {
			return fmt.Errorf("peer %q not found", peerName)
		}
		return fmt.Errorf("get peer: %w", err)
	}
	if host == "" {
		host = peer.DialHost()
	}

	if err := deps.DB.SetPeerAllowedGroups(ctx, peerName, groups); err != nil {
		return fmt.Errorf("set allowed groups: %w", err)
	}
	if err := deps.DB.BumpFleetRev(ctx); err != nil {
		return fmt.Errorf("bump fleet_rev: %w", err)
	}

	if skip, notice := skipPushNotice(peer); skip {
		deps.info(peerName, notice)
		return nil
	}

	instanceKey, err := EnsureInstanceKey(ctx, deps.DB)
	if err != nil {
		return fmt.Errorf("ensure instance key: %w", err)
	}

	pushOpts := SelfPushOptions(deps.DataDir, SelfIdentFor(ctx, deps.DB, hostname), deps.PeerPass)
	pushOpts.User = pushUser(peer)
	deps.emit(Event{Type: EventPeerStart, Peer: peerName})
	pusher, err := dialPush(ctx, deps, host, pushOpts)
	if err != nil {
		err = fmt.Errorf("ssh dial %s: %w", host, err)
		deps.emit(Event{Type: EventPeerFailed, Peer: peerName, Err: err})
		return err
	}
	defer pusher.Close()

	fail := func(err error) error {
		deps.emit(Event{Type: EventPeerFailed, Peer: peerName, Err: err})
		return err
	}

	// Inbound trust lives in <home>/.ssh/authorized_keys, isolated per CA —
	// rewrite it in place, no reload.
	caPub, err := loadCAPublicKey(deps.DataDir)
	if err != nil {
		return fail(err)
	}
	remote := PeerAuthorizedKeysRemotePath(peer)
	existing, err := pusher.ReadFile(ctx, remote)
	if err != nil {
		return fail(fmt.Errorf("read %s: %w", remote, err))
	}
	newContent, err := peerfiles.RewritePrincipals(existing, caPub, groups)
	if err != nil {
		return fail(fmt.Errorf("rewrite authorized_keys: %w", err))
	}
	if err := pusher.WriteFileAtomic(ctx, remote, newContent, fs.FileMode(0644)); err != nil {
		return fail(fmt.Errorf("write %s: %w", remote, err))
	}
	if err := SplicePeerConfig(ctx, pusher, deps.DB, peer, instanceKey); err != nil {
		return fail(fmt.Errorf("splice ssh config: %w", err))
	}
	if err := pusher.VerifyHealth(ctx); err != nil {
		return fail(fmt.Errorf("verify health: %w", err))
	}

	deps.emit(Event{Type: EventPeerDone, Peer: peerName})
	return nil
}

// groupCascade is the affected-peer view of one group: its members, the peers
// allowing it, and their sorted union.
type groupCascade struct {
	members      []string
	memberSet    map[string]struct{}
	allowedBySet map[string]struct{}
	affected     []string
}

func loadGroupCascade(ctx context.Context, d *db.DB, name string) (groupCascade, error) {
	members, err := d.GetGroupMembers(ctx, name)
	if err != nil {
		return groupCascade{}, fmt.Errorf("get group members: %w", err)
	}
	allowedBy, err := d.GetGroupAllowedBy(ctx, name)
	if err != nil {
		return groupCascade{}, fmt.Errorf("get group allowed-by: %w", err)
	}

	memberSet := make(map[string]struct{}, len(members))
	for _, m := range members {
		memberSet[m] = struct{}{}
	}
	allowedBySet := make(map[string]struct{}, len(allowedBy))
	for _, a := range allowedBy {
		allowedBySet[a] = struct{}{}
	}
	affectedSet := make(map[string]struct{}, len(members)+len(allowedBy))
	for k := range memberSet {
		affectedSet[k] = struct{}{}
	}
	for k := range allowedBySet {
		affectedSet[k] = struct{}{}
	}
	affected := make([]string, 0, len(affectedSet))
	for k := range affectedSet {
		affected = append(affected, k)
	}
	sort.Strings(affected)

	return groupCascade{members: members, memberSet: memberSet, allowedBySet: allowedBySet, affected: affected}, nil
}

// signAndStorePeerCert re-signs a member peer's cert with the given groups and
// persists the new cert + serial.
func signAndStorePeerCert(ctx context.Context, d *db.DB, caObj *ca.CA, peer *db.Peer, groups []string) ([]byte, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey(peer.AuthorizedKey)
	if err != nil {
		return nil, fmt.Errorf("parse peer pubkey %q: %w", peer.Name, err)
	}
	principals := append([]string{peer.Name}, groups...)
	certBytes, serial, err := caObj.SignCert(ca.SignOptions{
		Pubkey:     pk,
		KeyID:      peer.Name,
		Principals: principals,
	})
	if err != nil {
		return nil, fmt.Errorf("sign cert %q: %w", peer.Name, err)
	}
	if err := d.SetPeerCert(ctx, peer.Name, certBytes, serial); err != nil {
		return nil, fmt.Errorf("set peer cert %q: %w", peer.Name, err)
	}
	return certBytes, nil
}

// pushGroupCascade delivers one peer's share of a group rename/delete: the
// re-signed cert (members), the rewritten authorized_keys principals (allowing
// peers), optionally the spliced client config, then a health check.
func pushGroupCascade(ctx context.Context, deps Deps, self SelfIdent, peer *db.Peer, instanceKey string, caPub ssh.PublicKey, isMember bool, certBytes []byte, isAllow bool, allowed []string, splice bool) error {
	pushOpts := SelfPushOptions(deps.DataDir, self, deps.PeerPass)
	pushOpts.User = pushUser(peer)
	host := peer.DialHost()
	pusher, err := dialPush(ctx, deps, host, pushOpts)
	if err != nil {
		return fmt.Errorf("ssh dial %s: %w", host, err)
	}
	defer pusher.Close()

	if isMember {
		certPath := PeerCertRemotePath(peer, instanceKey)
		if err := pusher.WriteFileAtomic(ctx, certPath, certBytes, fs.FileMode(0644)); err != nil {
			return fmt.Errorf("write cert: %w", err)
		}
	}

	if isAllow {
		remote := PeerAuthorizedKeysRemotePath(peer)
		existing, err := pusher.ReadFile(ctx, remote)
		if err != nil {
			return fmt.Errorf("read %s: %w", remote, err)
		}
		newContent, err := peerfiles.RewritePrincipals(existing, caPub, allowed)
		if err != nil {
			return fmt.Errorf("rewrite authorized_keys: %w", err)
		}
		if err := pusher.WriteFileAtomic(ctx, remote, newContent, fs.FileMode(0644)); err != nil {
			return fmt.Errorf("write %s: %w", remote, err)
		}
	}

	if splice {
		if err := SplicePeerConfig(ctx, pusher, deps.DB, peer, instanceKey); err != nil {
			return fmt.Errorf("splice ssh config: %w", err)
		}
	}

	if err := pusher.VerifyHealth(ctx); err != nil {
		return fmt.Errorf("verify health: %w", err)
	}
	return nil
}

func loadCAPublicKey(dataDir string) (ssh.PublicKey, error) {
	caPubBytes, err := ca.LoadPublicKey(filepath.Join(dataDir, "ca"))
	if err != nil {
		return nil, fmt.Errorf("load ca public key: %w", err)
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey(caPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca pubkey: %w", err)
	}
	return caPub, nil
}

func removeStr(xs []string, v string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}
