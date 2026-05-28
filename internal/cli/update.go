package cli

import (
	"context"
	"errors"
	"fmt"
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
				if err := d.EnsureGroup(ctx, g); err != nil {
					return err
				}
			}
			if err := d.SetPeerGroups(ctx, name, groups); err != nil {
				return fmt.Errorf("set peer groups: %w", err)
			}
			if err := d.UpdatePeerCertSerial(ctx, name, serial); err != nil {
				return fmt.Errorf("update peer cert serial: %w", err)
			}

			instanceKey, err := EnsureInstanceKey(ctx, d)
			if err != nil {
				return fmt.Errorf("ensure instance key: %w", err)
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
			// v1 user-mode and all v2 peers read trust per-connection from
			// authorized_keys, so no sshd reload is needed. Only legacy v1
			// root peers need a reload to re-evaluate HostCertificate /
			// TrustedUserCAKeys.
			if peer.Mode != db.ModeUser && peer.LayoutVersion < peerfiles.LayoutV2 {
				if err := pusher.ReloadSSHD(ctx); err != nil {
					return fmt.Errorf("reload sshd: %w", err)
				}
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
// the DB: the layout the self files were written at, the target user owning
// <home>/.ssh/, and (for v2) the per-instance key namespacing the files.
type selfIdent struct {
	layout      int
	targetUser  string
	instanceKey string
	resolved    bool
}

// resolveSelfIdent reads the manager's own peer row + instance key from the DB.
// The manager peer is named for the host certhold runs on (os.Hostname at init).
// When the row is absent (e.g. before init, or a renamed host) resolved stays
// false so selfPushOptions falls back to the historical v1 root layout.
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
	return selfIdent{layout: self.LayoutVersion, targetUser: selfHomeUser(self), instanceKey: key, resolved: true}
}

func selfHomeUser(p *db.Peer) string {
	if p.Mode == db.ModeRoot || p.TargetUser == "" {
		return "root"
	}
	return p.TargetUser
}

var osHostname = os.Hostname

// selfPushOptions assembles the sshpush.Options that point at certhold's own
// peer cert + key + known_hosts files, resolved DB-first from the manager's own
// layout_version + instance key. v1 self files live under self/etc/ssh/
// (root) or self/home/<user>/.ssh/; v2 self files are namespaced under
// self/<home>/.ssh/id_ed25519_<key>. When the manager row is unknown, default
// to the historical v1 root layout so callers without an init still resolve.
func selfPushOptions(dataDir string, self selfIdent, peerPassFn func() ([]byte, error)) sshpush.Options {
	if self.resolved && self.layout >= peerfiles.LayoutV2 {
		homeRel := strings.TrimPrefix(peerfiles.HomeOf(self.targetUser), "/")
		base := filepath.Join(dataDir, "self", homeRel, ".ssh")
		return sshpush.Options{
			CertPath:       filepath.Join(base, peerfiles.V2CertFileName(self.instanceKey)),
			KeyPath:        filepath.Join(base, peerfiles.V2KeyFileName(self.instanceKey)),
			KnownHostsPath: filepath.Join(base, "known_hosts"),
			PassphraseFn:   peerPassFn,
		}
	}
	if self.resolved && self.targetUser != "root" {
		base := filepath.Join(dataDir, "self", "home", self.targetUser, ".ssh")
		return sshpush.Options{
			CertPath:       filepath.Join(base, "id_ed25519-cert.pub"),
			KeyPath:        filepath.Join(base, "id_ed25519"),
			KnownHostsPath: filepath.Join(base, "known_hosts"),
			PassphraseFn:   peerPassFn,
		}
	}
	rootSSH := filepath.Join(dataDir, "self", "etc", "ssh")
	return sshpush.Options{
		CertPath:       filepath.Join(rootSSH, "peer_ed25519-cert.pub"),
		KeyPath:        filepath.Join(rootSSH, "peer_ed25519"),
		KnownHostsPath: filepath.Join(rootSSH, "ca_known_hosts"),
		PassphraseFn:   peerPassFn,
	}
}

func peerCertRemotePath(p *db.Peer, instanceKey string) string {
	return peerfiles.PathsFor(p.LayoutVersion, p.Mode, p.TargetUser, instanceKey).Cert
}

func peerAuthorizedKeysRemotePath(p *db.Peer) string {
	return peerfiles.PathsFor(p.LayoutVersion, p.Mode, p.TargetUser, "").AuthorizedKeys
}
