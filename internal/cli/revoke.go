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
		Short: "Decommission a peer: by default clear certhold off it and delete its row; --rekey rotates the CA instead",
		Long: "Revoke a peer.\n\n" +
			"Default: SSH into the (reachable, inbound) peer, strip certhold's config\n" +
			"block, identity files, and cert-authority trust line, then delete its DB\n" +
			"row. A no-inbound/client or unreachable peer is rejected without deleting;\n" +
			"use `certhold remove` (DB-only) or `--rekey` for those.\n\n" +
			"--rekey: rotate the CA, re-signing and pushing to every remaining peer,\n" +
			"then delete the revoked row. The revoked host is never contacted — use this\n" +
			"for a compromised or unreachable peer.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRevoke(cmd, args[0])
		},
	}
	cmd.Flags().Bool("rekey", false, "rotate the CA around the peer instead of clearing it (for a compromised or unreachable peer)")
	cmd.Flags().String("hostname", "", "certhold's own peer name for the --rekey path (default: os.Hostname())")
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
	rekey, err := cmd.Flags().GetBool("rekey")
	if err != nil {
		return fmt.Errorf("get rekey: %w", err)
	}

	deps := opsDeps(cmd, d, dataDir, caUnlock, peerUnlock, rekeyDial)
	return ops.RevokePeer(ctx, deps, name, hostname, rekey)
}
