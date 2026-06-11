package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/ops"
)

func newRevokeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke <name>",
		Short: "Revoke a peer via a partial CA rekey that excludes it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRevoke(cmd, args[0])
		},
	}
	cmd.Flags().String("hostname", "", "certhold's own peer name for the rekey-revoke (default: os.Hostname())")
	return cmd
}

func runRevoke(cmd *cobra.Command, name string) error {
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

	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	caUnlock := newCAUnlocker()
	defer caUnlock.Zero()
	peerUnlock := newPeerUnlocker()
	defer peerUnlock.Zero()

	hostname, err := cmd.Flags().GetString("hostname")
	if err != nil {
		return fmt.Errorf("get hostname: %w", err)
	}

	deps := opsDeps(cmd, d, dataDir, caUnlock, peerUnlock, rekeyDial)
	return ops.RevokePeer(ctx, deps, name, hostname)
}
