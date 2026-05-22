package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/token"
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

			mode, err := cmd.Flags().GetString("mode")
			if err != nil {
				return err
			}
			if mode != db.ModeUser && mode != db.ModeRoot {
				return fmt.Errorf("--mode must be 'user' or 'root', got %q", mode)
			}
			targetUser, err := cmd.Flags().GetString("user")
			if err != nil {
				return err
			}
			if mode == db.ModeRoot {
				targetUser = ""
			}

			groups, err := parseGroups(groupsCSV)
			if err != nil {
				return err
			}

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

			if _, err := d.GetPeer(ctx, name); err == nil {
				return fmt.Errorf("peer %q already exists", name)
			} else if !errors.Is(err, db.ErrPeerNotFound) {
				return fmt.Errorf("lookup peer: %w", err)
			}

			for _, g := range groups {
				if err := d.EnsureGroup(ctx, g); err != nil {
					return err
				}
			}

			tok, err := token.Generate()
			if err != nil {
				return fmt.Errorf("generate token: %w", err)
			}

			if err := d.InsertTokenWithMode(ctx, tok, name, strings.Join(groups, ","), mode, targetUser); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "curl -kfsSL %s/enroll/%s.sh | bash\n", baseURL, tok)
			return nil
		},
	}

	cmd.Flags().String("groups", "", "comma-separated list of groups for the new peer (required)")
	cmd.Flags().String("base-url", legacyBaseURL, "base URL of certhold's enroll endpoint (defaults to value persisted by `init`, then $CERTHOLD_BASE_URL, then https://certhold.home.lan)")
	cmd.Flags().String("mode", db.ModeUser, "install mode: 'user' (default, files under ~user/.ssh) or 'root' (files under /etc/ssh)")
	cmd.Flags().String("user", "", "Unix user owning the ~/.ssh files; when set, acts as a hard constraint at install time (only meaningful with --mode=user)")
	_ = cmd.MarkFlagRequired("groups")

	return cmd
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
