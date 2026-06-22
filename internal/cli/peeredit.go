package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/ops"
	"github.com/shudza/certhold/internal/sshpush"
)

// peerEditDial is overridden in tests.
var peerEditDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
	return sshpush.Dial(ctx, host, opts)
}

func newAddressCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "address <name> <addr>",
		Short: "Set (or clear) the network address the manager dials to reach a peer",
		Long: "Address records where the manager dials this peer for pushes. Pass an empty " +
			"string to clear it so the manager dials by name. This is a manager-state change " +
			"only — no peer is contacted; other peers pick up the new Host alias on their next refresh.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAddress(cmd, args[0], args[1])
		},
	}
}

func runAddress(cmd *cobra.Command, name, address string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
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

	deps := ops.Deps{
		DB:      d,
		OnEvent: opsEventPrinter(cmd.OutOrStdout(), cmd.ErrOrStderr()),
	}
	return ops.SetPeerAddress(ctx, deps, name, address)
}

func newMakeClientCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "make-client <name>",
		Short: "Convert an inbound peer into a client (stops it accepting fleet inbound SSH)",
		Long: "Make-client dials the peer while it is still reachable and removes the certhold " +
			"cert-authority trust line from its ~/.ssh/authorized_keys, so it no longer accepts " +
			"inbound SSH from the fleet. The peer's own identity and config are left intact, so its " +
			"outbound access keeps working. This is one-way: the manager cannot push to a client " +
			"peer, so converting back requires re-enrollment. If the peer is unreachable the change " +
			"is refused (the flag is not flipped while the peer still accepts inbound).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMakeClient(cmd, args[0])
		},
	}
}

func runMakeClient(cmd *cobra.Command, name string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
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

	peerUnlock := newPeerUnlocker()
	defer peerUnlock.Zero()
	caUnlock := newCAUnlocker()
	defer caUnlock.Zero()

	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	hostname, err := osHostname()
	if err != nil {
		return fmt.Errorf("hostname: %w", err)
	}

	deps := opsDeps(cmd, d, dataDir, caUnlock, peerUnlock, peerEditDial)
	return ops.MakeClient(ctx, deps, name, hostname)
}
