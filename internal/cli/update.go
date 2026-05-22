package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
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
			if host == "" {
				host = name
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

			caObj, err := ca.Load(filepath.Join(dataDir, "ca"))
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

			selfSSH := filepath.Join(dataDir, "self", "etc", "ssh")
			pusher, err := dialFn(ctx, host, sshpush.Options{
				CertPath:       filepath.Join(selfSSH, "peer_ed25519-cert.pub"),
				KeyPath:        filepath.Join(selfSSH, "peer_ed25519"),
				KnownHostsPath: filepath.Join(selfSSH, "ca_known_hosts"),
			})
			if err != nil {
				return fmt.Errorf("ssh dial %s: %w", host, err)
			}
			defer pusher.Close()

			if err := pusher.WriteFileAtomic(ctx, "/etc/ssh/peer_ed25519-cert.pub", certBytes, 0644); err != nil {
				return fmt.Errorf("write cert: %w", err)
			}
			if err := pusher.ReloadSSHD(ctx); err != nil {
				return fmt.Errorf("reload sshd: %w", err)
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
