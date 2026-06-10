package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/tui"
	"github.com/spf13/cobra"
)

func newTuiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Interactive read-only fleet dashboard",
		RunE: func(cmd *cobra.Command, args []string) error {
			dbPath, err := cmd.Flags().GetString("db")
			if err != nil {
				return err
			}
			if _, err := os.Stat(dbPath); err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("no state database at %s — run 'certhold init' first", dbPath)
				}
				return err
			}
			d, err := db.Open(dbPath)
			if err != nil {
				return err
			}
			defer d.Close()

			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			if _, err := d.ActiveCAVersion(ctx); err != nil {
				if errors.Is(err, db.ErrNoActiveCA) {
					return fmt.Errorf("state database at %s is not initialized — run 'certhold init' first", dbPath)
				}
				return err
			}
			return tui.Run(ctx, d, dbPath, cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}
}
