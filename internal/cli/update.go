package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/ops"
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

			d, err := db.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer d.Close()

			deps := opsDeps(cmd, d, dataDir, caUnlock, peerUnlock, dialFn)
			return ops.UpdatePeer(ctx, deps, name, groups, host, "")
		},
	}
	cmd.Flags().String("groups", "", "comma-separated list of groups (required)")
	cmd.Flags().String("host", "", "host to push the cert to (default: <name>)")
	_ = cmd.MarkFlagRequired("groups")
	return cmd
}

func clientPeerNotice(w io.Writer, name string) {
	fmt.Fprintf(w, "%s\n", ops.ClientPeerNoticeMsg(name))
}

func splicePeerConfig(ctx context.Context, pusher sshpush.Pusher, d *db.DB, peer *db.Peer, instanceKey string) error {
	return ops.SplicePeerConfig(ctx, pusher, d, peer, instanceKey)
}
