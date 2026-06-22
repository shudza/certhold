package ops

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/peerfiles"
	"github.com/shudza/certhold/internal/sshpush"
)

// dialPush dials a push target through deps.Dial, wiring confirm-on-unknown-host
// when deps.HostKeyConfirm is set. With it nil the dial is unchanged (an unknown
// host fails strictly, as before). When set, an unknown host key is offered to
// the operator via deps.HostKeyConfirm(host, sha256-fingerprint, key-type); on
// accept the key is learned (recorded by sshpush) and an operator notice is
// emitted, on reject the strict unknown-host error surfaces, and a mismatch
// always fails without consulting the operator.
func dialPush(ctx context.Context, deps Deps, host string, opts sshpush.Options) (sshpush.Pusher, error) {
	if deps.HostKeyConfirm == nil {
		return deps.Dial(ctx, host, opts)
	}
	var learned bool
	opts.HostKeyConfirmFn = func(h string, key ssh.PublicKey) (bool, error) {
		ok, err := deps.HostKeyConfirm(h, ssh.FingerprintSHA256(key), key.Type())
		if err != nil {
			return false, err
		}
		if ok {
			learned = true
		}
		return ok, nil
	}
	pusher, err := deps.Dial(ctx, host, opts)
	if err == nil && learned {
		deps.info(host, LearnedHostKeyMsg(host))
	}
	return pusher, err
}

// SelfIdent describes the manager's own outbound SSH identity as recorded in
// the DB: the target user owning <home>/.ssh/ and the per-instance key
// namespacing the self files. When unresolved the v2 root home (/root) is used.
type SelfIdent struct {
	TargetUser  string
	InstanceKey string
	Resolved    bool
}

// SelfIdentFor reads the manager's own peer row + instance key from the DB.
// The manager peer is named for the host certhold runs on (os.Hostname at
// init). When the row is absent (e.g. before init, or a renamed host) Resolved
// stays false and SelfPushOptions targets /root/.ssh.
func SelfIdentFor(ctx context.Context, d *db.DB, host string) SelfIdent {
	if host == "" {
		return SelfIdent{}
	}
	self, err := d.GetPeer(ctx, host)
	if err != nil {
		return SelfIdent{}
	}
	key, _, _ := d.GetMeta(ctx, db.MetaInstanceKey)
	return SelfIdent{TargetUser: selfHomeUser(self), InstanceKey: key, Resolved: true}
}

func resolveSelfIdent(ctx context.Context, d *db.DB) SelfIdent {
	host, err := os.Hostname()
	if err != nil {
		return SelfIdent{}
	}
	return SelfIdentFor(ctx, d, host)
}

func selfHomeUser(p *db.Peer) string {
	if p.TargetUser == "" {
		return "root"
	}
	return p.TargetUser
}

// SelfPushOptions assembles the sshpush.Options that point at certhold's own
// peer cert + key + known_hosts files. Self identity is always the v2
// namespaced file set under self/<home>/.ssh/id_ed25519_<key>; an unresolved
// manager row targets /root/.ssh.
func SelfPushOptions(dataDir string, self SelfIdent, peerPassFn func() ([]byte, error)) sshpush.Options {
	user := self.TargetUser
	if user == "" {
		user = "root"
	}
	homeRel := strings.TrimPrefix(peerfiles.HomeOf(user), "/")
	base := filepath.Join(dataDir, "self", homeRel, ".ssh")
	return sshpush.Options{
		CertPath:       filepath.Join(base, peerfiles.V2CertFileName(self.InstanceKey)),
		KeyPath:        filepath.Join(base, peerfiles.V2KeyFileName(self.InstanceKey)),
		KnownHostsPath: filepath.Join(base, "known_hosts"),
		PassphraseFn:   peerPassFn,
	}
}

func PeerCertRemotePath(p *db.Peer, instanceKey string) string {
	return peerfiles.PathsFor(p.TargetUser, instanceKey).Cert
}

func PeerAuthorizedKeysRemotePath(p *db.Peer) string {
	return peerfiles.PathsFor(p.TargetUser, "").AuthorizedKeys
}

func pushUser(p *db.Peer) string {
	if p.TargetUser != "" {
		return p.TargetUser
	}
	return "root"
}

// v2ConfigBlockForHosts renders the keyed client-config block carrying one
// Host alias stanza per reachable peer.
func v2ConfigBlockForHosts(instanceKey string, hosts []db.ReachableHost) string {
	entries := make([]peerfiles.HostEntry, 0, len(hosts))
	for _, h := range hosts {
		entries = append(entries, peerfiles.HostEntry{Name: h.Name, Address: h.Address, User: h.TargetUser})
	}
	return peerfiles.V2SshClientBlockWithHosts(instanceKey, entries)
}

// SplicePeerConfig recomputes the peer's reachable-host config block and
// splices it into the peer's <home>/.ssh/config over the open pusher.
func SplicePeerConfig(ctx context.Context, pusher sshpush.Pusher, d *db.DB, peer *db.Peer, instanceKey string) error {
	hosts, err := d.ReachableHosts(ctx, peer.Name)
	if err != nil {
		return fmt.Errorf("reachable hosts for %s: %w", peer.Name, err)
	}
	block := v2ConfigBlockForHosts(instanceKey, hosts)
	return pusher.SpliceConfigBlock(ctx, peerfiles.PathsFor(peer.TargetUser, instanceKey).ConfigTarget, instanceKey, block)
}

func writeFileAtomicLocal(path string, content []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("rename %s -> %s: %w", tmpName, path, err)
	}
	return nil
}
