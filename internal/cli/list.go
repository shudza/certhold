package cli

import (
	"context"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/shudza/certhold/internal/db"
	"github.com/spf13/cobra"
)

func newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List peers or groups",
		RunE: func(cmd *cobra.Command, args []string) error {
			peers, err := cmd.Flags().GetBool("peers")
			if err != nil {
				return err
			}
			groups, err := cmd.Flags().GetBool("groups")
			if err != nil {
				return err
			}
			dbPath, err := cmd.Flags().GetString("db")
			if err != nil {
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
			if groups {
				return runListGroups(ctx, cmd, d)
			}
			_ = peers
			return runListPeers(ctx, cmd, d)
		},
	}
	cmd.Flags().Bool("peers", false, "list peers (default)")
	cmd.Flags().Bool("groups", false, "list groups with peer counts")
	cmd.MarkFlagsMutuallyExclusive("peers", "groups")
	return cmd
}

func runListPeers(ctx context.Context, cmd *cobra.Command, d *db.DB) error {
	peers, err := d.ListPeers(ctx)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME \tGROUPS \tALLOWED \tINBOUND \tREVOKED")
	for _, p := range peers {
		gs, err := d.GetPeerGroups(ctx, p.Name)
		if err != nil {
			return err
		}
		as, err := d.GetPeerAllowedGroups(ctx, p.Name)
		if err != nil {
			return err
		}
		inbound := "N"
		if p.Inbound {
			inbound = "Y"
		}
		revoked := "N"
		if p.Revoked {
			revoked = "Y"
		}
		fmt.Fprintf(w, "%s \t%s \t%s \t%s \t%s\n",
			p.Name, strings.Join(gs, ","), strings.Join(as, ","), inbound, revoked)
	}
	return w.Flush()
}

func runListGroups(ctx context.Context, cmd *cobra.Command, d *db.DB) error {
	gs, err := d.ListGroupsWithPeerCount(ctx)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME \tPEERS")
	for _, g := range gs {
		fmt.Fprintf(w, "%s \t%d\n", g.Name, g.PeerCount)
	}
	return w.Flush()
}
