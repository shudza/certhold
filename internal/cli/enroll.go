package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/peerfiles"
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

			instanceKey, err := EnsureInstanceKey(ctx, d)
			if err != nil {
				return fmt.Errorf("ensure instance key: %w", err)
			}

			if _, err := d.GetPeer(ctx, name); err == nil {
				return fmt.Errorf("peer %q already exists", name)
			} else if !errors.Is(err, db.ErrPeerNotFound) {
				return fmt.Errorf("lookup peer: %w", err)
			}

			caUnlock := newCAUnlocker()
			defer caUnlock.Zero()
			caObj, err := ca.LoadWithPassphrase(filepath.Join(dataDir, "ca"), caUnlock.get)
			if err != nil {
				return fmt.Errorf("load ca: %w", err)
			}

			priv, pubAuth, sshPub, err := ca.GeneratePeerKey()
			if err != nil {
				return fmt.Errorf("generate peer key: %w", err)
			}
			defer zeroBytes(priv)

			principals := append([]string{name}, groups...)
			certBytes, serial, err := caObj.SignCert(ca.SignOptions{
				Pubkey:     sshPub,
				KeyID:      name,
				Principals: principals,
			})
			if err != nil {
				return fmt.Errorf("sign cert: %w", err)
			}

			fingerprint := ssh.FingerprintSHA256(sshPub)

			// Newly enrolled peers are layout v2 for BOTH modes: root mode is
			// implemented as user-mode trust targeting /root, so the tarball
			// is always the namespaced user-style file set.
			tarballUser := targetUser
			if mode == db.ModeRoot {
				tarballUser = "root"
			}
			tarball, err := peerfiles.BuildUser(peerfiles.UserPeerFiles{
				TargetUser:  tarballUser,
				PrivKey:     priv,
				CertPub:     certBytes,
				CAPub:       caObj.PublicKeyAuthorizedKey(),
				Principals:  groups,
				Layout:      peerfiles.CurrentLayout,
				InstanceKey: instanceKey,
			})
			if err != nil {
				return fmt.Errorf("build tarball: %w", err)
			}

			tok, err := token.Generate()
			if err != nil {
				return fmt.Errorf("generate token: %w", err)
			}

			if err := d.WithTx(ctx, func(tx *db.Tx) error {
				if err := tx.InsertTokenWithMode(ctx, tok, name, strings.Join(groups, ","), mode, targetUser, tarball); err != nil {
					return err
				}
				if err := tx.InsertPeerWithMode(ctx, name, serial, fingerprint, pubAuth, mode, targetUser, peerfiles.CurrentLayout); err != nil {
					return fmt.Errorf("insert peer: %w", err)
				}
				for _, g := range groups {
					if err := tx.EnsureGroup(ctx, g); err != nil {
						return err
					}
				}
				if err := tx.SetPeerGroups(ctx, name, groups); err != nil {
					return fmt.Errorf("set peer groups: %w", err)
				}
				if err := tx.SetPeerAllowedGroups(ctx, name, groups); err != nil {
					return fmt.Errorf("set peer allowed groups: %w", err)
				}
				return nil
			}); err != nil {
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
	cmd.Flags().String("hostname", "", "deprecated/unused under layout v2 (host trust is TOFU known_hosts)")
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
