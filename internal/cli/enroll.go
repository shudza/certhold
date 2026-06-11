package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/ops"
)

func newEnrollCmd() *cobra.Command {
	const legacyBaseURL = "https://certhold.home.lan"

	cmd := &cobra.Command{
		Use:   "enroll <name>",
		Short: "Mint an enrollment token and print the onboarding one-liner",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			groupsCSV, err := cmd.Flags().GetString("groups")
			if err != nil {
				return err
			}
			baseURL, err := resolveBaseURL(cmd)
			if err != nil {
				return err
			}
			baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "\n/")

			targetUser, err := cmd.Flags().GetString("user")
			if err != nil {
				return err
			}
			address, err := cmd.Flags().GetString("address")
			if err != nil {
				return err
			}

			noInbound, err := cmd.Flags().GetBool("no-inbound")
			if err != nil {
				return err
			}
			client, err := cmd.Flags().GetBool("client")
			if err != nil {
				return err
			}
			clientMode := noInbound || client

			groups, err := parseGroups(groupsCSV)
			if err != nil {
				return err
			}

			dataDir, err := cmd.Root().PersistentFlags().GetString("data-dir")
			if err != nil {
				return fmt.Errorf("get data-dir: %w", err)
			}
			dataDir = expandHome(dataDir)

			dbPath, err := cmd.Flags().GetString("db")
			if err != nil {
				return err
			}
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

			deps := ops.Deps{DB: d, DataDir: dataDir, CAUnlock: caUnlock.get}
			res, err := ops.MintEnroll(ctx, deps, ops.EnrollSpec{
				Name:    name,
				Groups:  groups,
				Allowed: groups,
				User:    targetUser,
				Address: address,
				Client:  clientMode,
				BaseURL: baseURL,
			})
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", res.OneLiner)
			if clientMode {
				fmt.Fprintf(cmd.OutOrStdout(), "client-style peer; manager cannot push to it; updates arrive via `certhold-cli refresh`.\n")
			}
			return nil
		},
	}

	cmd.Flags().String("groups", "", "comma-separated list of groups for the new peer (required)")
	cmd.Flags().String("base-url", legacyBaseURL, "base URL of certhold's enroll endpoint (defaults to value persisted by `init`, then $CERTHOLD_BASE_URL, then https://certhold.home.lan)")
	cmd.Flags().String("user", "", "Unix user owning the ~/.ssh files; when set, acts as a hard constraint at install time (--user root targets /root/.ssh)")
	cmd.Flags().String("hostname", "", "deprecated/unused under layout v2 (host trust is TOFU known_hosts)")
	cmd.Flags().String("address", "", "network address (host or IP) certhold uses to SSH to this peer; defaults to the source IP seen at install, then the peer name")
	cmd.Flags().Bool("no-inbound", false, "enroll a client-style peer: no inbound trust line, other peers cannot SSH into it, updates arrive via certhold-cli refresh")
	cmd.Flags().Bool("client", false, "alias for --no-inbound")
	_ = cmd.MarkFlagRequired("groups")

	return cmd
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func resolveBaseURL(cmd *cobra.Command) (string, error) {
	if cmd.Flags().Changed("base-url") {
		return cmd.Flags().GetString("base-url")
	}
	if env := os.Getenv("CERTHOLD_BASE_URL"); env != "" {
		return env, nil
	}
	dataDir, err := cmd.Root().PersistentFlags().GetString("data-dir")
	if err == nil && dataDir != "" {
		if v, err := LoadBaseURL(expandHome(dataDir)); err == nil {
			return v, nil
		} else if !errors.Is(err, ErrNoBaseURL) {
			return "", err
		}
	}
	return cmd.Flags().GetString("base-url")
}

func parseGroups(csv string) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string
	for _, raw := range strings.Split(csv, ",") {
		g := strings.TrimSpace(raw)
		if g == "" {
			continue
		}
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	if len(out) == 0 {
		return nil, errors.New("--groups must contain at least one non-empty group")
	}
	return out, nil
}
