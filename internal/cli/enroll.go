package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/token"
)

func newEnrollCmd() *cobra.Command {
	defaultBaseURL := os.Getenv("CERTHOLD_BASE_URL")
	if defaultBaseURL == "" {
		defaultBaseURL = "https://certhold.home.lan"
	}

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
			baseURL, err := cmd.Flags().GetString("base-url")
			if err != nil {
				return err
			}
			baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "\n/")

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

			if err := d.InsertToken(ctx, tok, name, strings.Join(groups, ",")); err != nil {
				return err
			}

			payload := fmt.Sprintf("#!/usr/bin/env bash\nset -e\ncurl -fsSL %s/enroll/%s | tar -xzC /\nsystemctl reload sshd\n", baseURL, tok)
			encoded := base64.StdEncoding.EncodeToString([]byte(payload))
			fmt.Fprintf(cmd.OutOrStdout(), "echo \"%s\" | base64 -d | bash\n", encoded)
			return nil
		},
	}

	cmd.Flags().String("groups", "", "comma-separated list of groups for the new peer (required)")
	cmd.Flags().String("base-url", defaultBaseURL, "base URL of certhold's enroll endpoint")
	_ = cmd.MarkFlagRequired("groups")

	return cmd
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
