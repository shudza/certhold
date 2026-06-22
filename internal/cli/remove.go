package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/ops"
)

func newRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Forget a peer in manager state without contacting it (no SSH, no CA rekey)",
		Long: "Remove deletes a peer and its references from manager state. It makes no SSH " +
			"connection to the peer and does not rotate the CA, so it works even when the peer is " +
			"offline, dead, or already wiped.\n\n" +
			"The peer's host is left untouched: its installed cert and config stay in place until " +
			"the operator wipes them. To clean the host and rotate the CA so the peer's old cert " +
			"stops being accepted across the fleet, use 'certhold revoke' instead.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemove(cmd, args[0])
		},
	}
	return cmd
}

func runRemove(cmd *cobra.Command, name string) error {
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
	return ops.RemovePeer(ctx, deps, name)
}
