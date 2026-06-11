package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/ops"
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
	cmd.AddCommand(newGroupAllowCmd(), newGroupDisallowCmd(), newGroupCreateCmd(), newGroupShowCmd(), newGroupDeleteCmd(), newGroupRenameCmd())
	return cmd
}

// groupEventPrinter renders group-op events. Unlike opsEventPrinter it skips
// events without a Msg: group per-peer EventPeerDone is purely structural (the
// CLI historically printed nothing per pushed peer).
func groupEventPrinter(out, errOut io.Writer) func(ops.Event) {
	return func(e ops.Event) {
		switch e.Type {
		case ops.EventInfo, ops.EventPeerDone:
			if e.Msg != "" {
				fmt.Fprintf(out, "%s\n", e.Msg)
			}
		case ops.EventWarn:
			fmt.Fprintf(errOut, "%s\n", e.Msg)
		}
	}
}

func groupOpsDeps(cmd *cobra.Command, d *db.DB, dataDir string, caUnlock, peerUnlock *memoUnlocker) ops.Deps {
	return ops.Deps{
		DB:       d,
		DataDir:  dataDir,
		CAUnlock: caUnlock.get,
		PeerPass: peerUnlock.get,
		Dial:     ops.DialFn(groupDial),
		OnEvent:  groupEventPrinter(cmd.OutOrStdout(), cmd.ErrOrStderr()),
	}
}

func newGroupRenameCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rename <old> <new>",
		Short: "Rename a group and push the cascading rewrite to every affected peer",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGroupRename(cmd, args[0], args[1])
		},
	}
}

func runGroupRename(cmd *cobra.Command, oldName, newName string) error {
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

	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	caUnlock := newCAUnlocker()
	defer caUnlock.Zero()
	peerUnlock := newPeerUnlocker()
	defer peerUnlock.Zero()

	hostname, _ := osHostname()
	return ops.GroupRename(ctx, groupOpsDeps(cmd, d, dataDir, caUnlock, peerUnlock), oldName, newName, hostname)
}

func newGroupDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a group and push the cascading removal to every affected peer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGroupDelete(cmd, args[0])
		},
	}
}

func runGroupDelete(cmd *cobra.Command, name string) error {
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

	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	caUnlock := newCAUnlocker()
	defer caUnlock.Zero()
	peerUnlock := newPeerUnlocker()
	defer peerUnlock.Zero()

	hostname, _ := osHostname()
	return ops.GroupDelete(ctx, groupOpsDeps(cmd, d, dataDir, caUnlock, peerUnlock), name, hostname)
}

func newGroupCreateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGroupCreate(cmd, args[0])
		},
	}
}

func newGroupShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show a group's members and the peers that allow it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGroupShow(cmd, args[0])
		},
	}
}

func runGroupCreate(cmd *cobra.Command, name string) error {
	dbPath, err := cmd.Root().PersistentFlags().GetString("db")
	if err != nil {
		return fmt.Errorf("get db: %w", err)
	}
	dbPath = expandHome(dbPath)

	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	deps := ops.Deps{DB: d, OnEvent: groupEventPrinter(cmd.OutOrStdout(), cmd.ErrOrStderr())}
	return ops.GroupCreate(ctx, deps, name)
}

func runGroupShow(cmd *cobra.Command, name string) error {
	dbPath, err := cmd.Root().PersistentFlags().GetString("db")
	if err != nil {
		return fmt.Errorf("get db: %w", err)
	}
	dbPath = expandHome(dbPath)

	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	exists, err := d.GroupExists(ctx, name)
	if err != nil {
		return fmt.Errorf("group exists: %w", err)
	}
	if !exists {
		return fmt.Errorf("group %q does not exist", name)
	}

	members, err := d.GetGroupMembers(ctx, name)
	if err != nil {
		return fmt.Errorf("get group members: %w", err)
	}
	allowedBy, err := d.GetGroupAllowedBy(ctx, name)
	if err != nil {
		return fmt.Errorf("get group allowed-by: %w", err)
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "GROUP\t%s\n", name)
	fmt.Fprintf(w, "MEMBERS\t%s\n", joinOrNone(members))
	fmt.Fprintf(w, "ALLOWED BY\t%s\n", joinOrNone(allowedBy))
	return w.Flush()
}

func joinOrNone(xs []string) string {
	if len(xs) == 0 {
		return "(none)"
	}
	return strings.Join(xs, ",")
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
	if allow && !peer.Inbound {
		return fmt.Errorf("peer %s is a client-style peer (enrolled --no-inbound); it accepts no inbound connections", peerName)
	}

	current, err := d.GetPeerAllowedGroups(ctx, peerName)
	if err != nil {
		return fmt.Errorf("get allowed groups: %w", err)
	}

	if allow {
		exists, err := d.GroupExists(ctx, group)
		if err != nil {
			return fmt.Errorf("check group %q: %w", group, err)
		}
		if !exists {
			return fmt.Errorf("group %q does not exist (run \"certhold group create %s\" first)", group, group)
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

	caUnlock := newCAUnlocker()
	defer caUnlock.Zero()
	peerUnlock := newPeerUnlocker()
	defer peerUnlock.Zero()

	hostname, _ := osHostname()
	if err := ops.SetPeerAllowedGroups(ctx, groupOpsDeps(cmd, d, dataDir, caUnlock, peerUnlock), peerName, current, host, hostname); err != nil {
		return err
	}

	if allow {
		fmt.Fprintf(cmd.OutOrStdout(), "group %q allowed on %s\n", group, peerName)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "group %q disallowed on %s\n", group, peerName)
	}
	return nil
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
