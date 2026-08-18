package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/ops"
	"github.com/shudza/certhold/internal/tui"
	"github.com/spf13/cobra"
)

func newTuiCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Interactive fleet dashboard with in-place edit-groups and revoke",
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

			readOnly, err := cmd.Flags().GetBool("read-only")
			if err != nil {
				return err
			}

			dataDir, err := cmd.Root().PersistentFlags().GetString("data-dir")
			if err != nil {
				return fmt.Errorf("get data-dir: %w", err)
			}
			dataDir = expandHome(dataDir)
			hostname, _ := ops.SelfName(ctx, d)

			// BuildDeps wires ops.Deps from the TUI-owned passphrase closures
			// (which bridge to the masked modal), the host-key confirm closure
			// (which bridges to the host-key modal), and the event sink. revoke
			// rekeys, so it dials over rekeyDial like the CLI revoke command does.
			action := tui.ActionDeps{
				Hostname: hostname,
				BuildDeps: func(onEvent func(ops.Event), caUnlock, peerPass func() ([]byte, error), hostKeyConfirm func(host, fingerprint, keyType string) (bool, error)) ops.Deps {
					return ops.Deps{
						DB:             d,
						DataDir:        dataDir,
						CAUnlock:       caUnlock,
						PeerPass:       peerPass,
						Dial:           ops.DialFn(rekeyDial),
						OnEvent:        onEvent,
						HostKeyConfirm: hostKeyConfirm,
					}
				},
			}

			return tui.Run(ctx, d, dbPath, cmd.InOrStdin(), cmd.OutOrStdout(), tui.RunOptions{
				Action:   &action,
				ReadOnly: readOnly,
			})
		},
	}
	cmd.Flags().Bool("read-only", false, "disable all mutations (v1 dashboard behavior)")
	return cmd
}
