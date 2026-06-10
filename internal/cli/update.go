package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/peerfiles"
	"github.com/shudza/certhold/internal/sshpush"
)

var dialFn = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
	return sshpush.Dial(ctx, host, opts)
}

func newUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update <name>",
		Short: "Reissue a peer's cert with new groups and push it to the peer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			groupsCSV, err := cmd.Flags().GetString("groups")
			if err != nil {
				return err
			}
			host, err := cmd.Flags().GetString("host")
			if err != nil {
				return err
			}
			groups, err := parseGroups(groupsCSV)
			if err != nil {
				return err
			}

			dataDir, err := cmd.Root().PersistentFlags().GetString("data-dir")
			if err != nil {
				return fmt.Errorf("get data-dir: %w", err)
			}
			dbPath, err := cmd.Root().PersistentFlags().GetString("db")
			if err != nil {
				return fmt.Errorf("get db: %w", err)
			}
			dataDir = expandHome(dataDir)
			dbPath = expandHome(dbPath)

			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			caUnlock := newCAUnlocker()
			defer caUnlock.Zero()
			peerUnlock := newPeerUnlocker()
			defer peerUnlock.Zero()

			caObj, err := ca.LoadWithPassphrase(filepath.Join(dataDir, "ca"), caUnlock.get)
			if err != nil {
				return fmt.Errorf("load ca: %w", err)
			}

			d, err := db.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer d.Close()

			peer, err := d.GetPeer(ctx, name)
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

			principals := append([]string{name}, groups...)
			certBytes, serial, err := caObj.SignCert(ca.SignOptions{
				Pubkey:     pk,
				KeyID:      name,
				Principals: principals,
			})
			if err != nil {
				return fmt.Errorf("sign cert: %w", err)
			}

			for _, g := range groups {
				exists, err := d.GroupExists(ctx, g)
				if err != nil {
					return fmt.Errorf("check group %q: %w", g, err)
				}
				if !exists {
					return fmt.Errorf("group %q does not exist (run \"certhold group create %s\" first)", g, g)
				}
			}
			if err := d.SetPeerGroups(ctx, name, groups); err != nil {
				return fmt.Errorf("set peer groups: %w", err)
			}
			if err := d.SetPeerCert(ctx, name, certBytes, serial); err != nil {
				return fmt.Errorf("set peer cert: %w", err)
			}

			instanceKey, err := EnsureInstanceKey(ctx, d)
			if err != nil {
				return fmt.Errorf("ensure instance key: %w", err)
			}

			if err := d.BumpFleetRev(ctx); err != nil {
				return fmt.Errorf("bump fleet_rev: %w", err)
			}

			if !peer.Inbound {
				clientPeerNotice(cmd.OutOrStdout(), name)
				fmt.Fprintf(cmd.OutOrStdout(), "updated %s (serial %d)\n", name, serial)
				return nil
			}

			pushOpts := selfPushOptions(dataDir, resolveSelfIdent(ctx, d), peerUnlock.get)
			pushOpts.User = pushUser(peer)
			pusher, err := dialFn(ctx, host, pushOpts)
			if err != nil {
				return fmt.Errorf("ssh dial %s: %w", host, err)
			}
			defer pusher.Close()

			certPath := peerCertRemotePath(peer, instanceKey)
			if err := pusher.WriteFileAtomic(ctx, certPath, certBytes, 0644); err != nil {
				return fmt.Errorf("write cert: %w", err)
			}
			if err := splicePeerConfig(ctx, pusher, d, peer, instanceKey); err != nil {
				return fmt.Errorf("splice ssh config: %w", err)
			}
			if err := pusher.VerifyHealth(ctx); err != nil {
				return fmt.Errorf("verify health: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "updated %s (serial %d)\n", name, serial)
			return nil
		},
	}
	cmd.Flags().String("groups", "", "comma-separated list of groups (required)")
	cmd.Flags().String("host", "", "host to push the cert to (default: <name>)")
	_ = cmd.MarkFlagRequired("groups")
	return cmd
}

// selfIdent describes the manager's own outbound SSH identity as recorded in
// the DB: the target user owning <home>/.ssh/ and the per-instance key
// namespacing the self files. When unresolved the v2 root home (/root) is used.
type selfIdent struct {
	targetUser  string
	instanceKey string
	resolved    bool
}

// resolveSelfIdent reads the manager's own peer row + instance key from the DB.
// The manager peer is named for the host certhold runs on (os.Hostname at init).
// When the row is absent (e.g. before init, or a renamed host) resolved stays
// false and selfPushOptions targets /root/.ssh.
func resolveSelfIdent(ctx context.Context, d *db.DB) selfIdent {
	host, err := osHostname()
	if err != nil || host == "" {
		return selfIdent{}
	}
	self, err := d.GetPeer(ctx, host)
	if err != nil {
		return selfIdent{}
	}
	key, _, _ := d.GetMeta(ctx, db.MetaInstanceKey)
	return selfIdent{targetUser: selfHomeUser(self), instanceKey: key, resolved: true}
}

func selfHomeUser(p *db.Peer) string {
	if p.TargetUser == "" {
		return "root"
	}
	return p.TargetUser
}

var osHostname = os.Hostname

// selfPushOptions assembles the sshpush.Options that point at certhold's own
// peer cert + key + known_hosts files. Self identity is always the v2
// namespaced file set under self/<home>/.ssh/id_ed25519_<key>; an unresolved
// manager row targets /root/.ssh.
func selfPushOptions(dataDir string, self selfIdent, peerPassFn func() ([]byte, error)) sshpush.Options {
	user := self.targetUser
	if user == "" {
		user = "root"
	}
	homeRel := strings.TrimPrefix(peerfiles.HomeOf(user), "/")
	base := filepath.Join(dataDir, "self", homeRel, ".ssh")
	return sshpush.Options{
		CertPath:       filepath.Join(base, peerfiles.V2CertFileName(self.instanceKey)),
		KeyPath:        filepath.Join(base, peerfiles.V2KeyFileName(self.instanceKey)),
		KnownHostsPath: filepath.Join(base, "known_hosts"),
		PassphraseFn:   peerPassFn,
	}
}

func peerCertRemotePath(p *db.Peer, instanceKey string) string {
	return peerfiles.PathsFor(p.TargetUser, instanceKey).Cert
}

func peerAuthorizedKeysRemotePath(p *db.Peer) string {
	return peerfiles.PathsFor(p.TargetUser, "").AuthorizedKeys
}

// clientPeerNotice tells the operator a client-style (inbound=0) peer was not
// dialed: its DB-side changes land on its next pull.
func clientPeerNotice(w io.Writer, name string) {
	fmt.Fprintf(w, "client peer %s: changes pending until 'certhold-cli refresh' runs on it\n", name)
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

// splicePeerConfig recomputes the peer's reachable-host config block and
// splices it into the peer's <home>/.ssh/config over the open pusher.
func splicePeerConfig(ctx context.Context, pusher sshpush.Pusher, d *db.DB, peer *db.Peer, instanceKey string) error {
	hosts, err := d.ReachableHosts(ctx, peer.Name)
	if err != nil {
		return fmt.Errorf("reachable hosts for %s: %w", peer.Name, err)
	}
	block := v2ConfigBlockForHosts(instanceKey, hosts)
	return pusher.SpliceConfigBlock(ctx, peerfiles.PathsFor(peer.TargetUser, instanceKey).ConfigTarget, instanceKey, block)
}
