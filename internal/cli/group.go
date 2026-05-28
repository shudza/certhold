package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/peerfiles"
	"github.com/shudza/certhold/internal/sshpush"
)

// groupDial is overridden in tests.
var groupDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
	return sshpush.Dial(ctx, host, opts)
}

func newGroupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "group",
		Short: "Manage groups and group memberships",
	}
	cmd.AddCommand(newGroupAllowCmd(), newGroupDisallowCmd())
	return cmd
}

func newGroupAllowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "allow <group>",
		Short: "Allow a group as an incoming-connection principal on a peer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGroupAction(cmd, args[0], true)
		},
	}
	addGroupFlags(cmd)
	return cmd
}

func newGroupDisallowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "disallow <group>",
		Short: "Disallow a group as an incoming-connection principal on a peer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGroupAction(cmd, args[0], false)
		},
	}
	addGroupFlags(cmd)
	return cmd
}

func addGroupFlags(cmd *cobra.Command) {
	cmd.Flags().String("on", "", "peer to update (required)")
	cmd.Flags().String("host", "", "ssh host to connect to (default: same as --on)")
	_ = cmd.MarkFlagRequired("on")
}

func runGroupAction(cmd *cobra.Command, group string, allow bool) error {
	peerName, err := cmd.Flags().GetString("on")
	if err != nil {
		return err
	}
	host, err := cmd.Flags().GetString("host")
	if err != nil {
		return err
	}

	dbPath, err := cmd.Root().PersistentFlags().GetString("db")
	if err != nil {
		return fmt.Errorf("get db: %w", err)
	}
	dataDir, err := cmd.Root().PersistentFlags().GetString("data-dir")
	if err != nil {
		return fmt.Errorf("get data-dir: %w", err)
	}
	dbPath = expandHome(dbPath)
	dataDir = expandHome(dataDir)

	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	peer, err := d.GetPeer(ctx, peerName)
	if err != nil {
		if errors.Is(err, db.ErrPeerNotFound) {
			return fmt.Errorf("peer %q not found", peerName)
		}
		return fmt.Errorf("get peer: %w", err)
	}
	if host == "" {
		host = peer.DialHost()
	}

	current, err := d.GetPeerAllowedGroups(ctx, peerName)
	if err != nil {
		return fmt.Errorf("get allowed groups: %w", err)
	}

	if allow {
		if err := d.EnsureGroup(ctx, group); err != nil {
			return fmt.Errorf("ensure group: %w", err)
		}
		if contains(current, group) {
			fmt.Fprintf(cmd.OutOrStdout(), "group %q already allowed on %s\n", group, peerName)
			return nil
		}
		current = append(current, group)
	} else {
		if !contains(current, group) {
			fmt.Fprintf(cmd.OutOrStdout(), "group %q not currently allowed on %s\n", group, peerName)
			return nil
		}
		current = removeStr(current, group)
	}

	if err := d.SetPeerAllowedGroups(ctx, peerName, current); err != nil {
		return fmt.Errorf("set allowed groups: %w", err)
	}

	peerUnlock := newPeerUnlocker()
	defer peerUnlock.Zero()

	pushOpts := selfPushOptions(dataDir, resolveSelfIdent(ctx, d), peerUnlock.get)
	pushOpts.User = pushUser(peer)
	pusher, err := groupDial(ctx, host, pushOpts)
	if err != nil {
		return fmt.Errorf("ssh dial %s: %w", host, err)
	}
	defer pusher.Close()

	// Inbound trust lives in <home>/.ssh/authorized_keys, isolated per CA —
	// rewrite it in place, no reload.
	caPubBytes, err := ca.LoadPublicKey(filepath.Join(dataDir, "ca"))
	if err != nil {
		return fmt.Errorf("load ca public key: %w", err)
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey(caPubBytes)
	if err != nil {
		return fmt.Errorf("parse ca pubkey: %w", err)
	}
	remote := peerAuthorizedKeysRemotePath(peer)
	existing, err := pusher.ReadFile(ctx, remote)
	if err != nil {
		return fmt.Errorf("read %s: %w", remote, err)
	}
	newContent, err := peerfiles.RewritePrincipals(existing, caPub, current)
	if err != nil {
		return fmt.Errorf("rewrite authorized_keys: %w", err)
	}
	if err := pusher.WriteFileAtomic(ctx, remote, newContent, fs.FileMode(0644)); err != nil {
		return fmt.Errorf("write %s: %w", remote, err)
	}
	if err := pusher.VerifyHealth(ctx); err != nil {
		return fmt.Errorf("verify health: %w", err)
	}

	if allow {
		fmt.Fprintf(cmd.OutOrStdout(), "group %q allowed on %s\n", group, peerName)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "group %q disallowed on %s\n", group, peerName)
	}
	return nil
}

func pushUser(p *db.Peer) string {
	if p.Mode == db.ModeUser {
		if p.TargetUser != "" {
			return p.TargetUser
		}
		return "root"
	}
	return "root"
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
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
