package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/peerfiles"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

func newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize certhold (generate CA, self-enroll)",
		RunE: func(cmd *cobra.Command, args []string) error {
			dataDir, err := cmd.Root().PersistentFlags().GetString("data-dir")
			if err != nil {
				return fmt.Errorf("get data-dir: %w", err)
			}
			dbPath, err := cmd.Root().PersistentFlags().GetString("db")
			if err != nil {
				return fmt.Errorf("get db: %w", err)
			}
			hostname, err := cmd.Flags().GetString("hostname")
			if err != nil {
				return fmt.Errorf("get hostname: %w", err)
			}
			if hostname == "" {
				h, err := os.Hostname()
				if err != nil {
					return fmt.Errorf("hostname: %w", err)
				}
				hostname = h
			}
			mode, err := cmd.Flags().GetString("mode")
			if err != nil {
				return fmt.Errorf("get mode: %w", err)
			}
			if mode != db.ModeUser && mode != db.ModeRoot {
				return fmt.Errorf("--mode must be 'user' or 'root', got %q", mode)
			}
			targetUser, err := cmd.Flags().GetString("user")
			if err != nil {
				return fmt.Errorf("get user: %w", err)
			}
			if mode == db.ModeRoot {
				targetUser = ""
			} else if !cmd.Flags().Changed("user") {
				targetUser = currentUsername()
			}

			listenIP, err := cmd.Flags().GetString("listen-ip")
			if err != nil {
				return fmt.Errorf("get listen-ip: %w", err)
			}
			port, err := cmd.Flags().GetInt("port")
			if err != nil {
				return fmt.Errorf("get port: %w", err)
			}
			noPrompt, err := cmd.Flags().GetBool("no-prompt")
			if err != nil {
				return fmt.Errorf("get no-prompt: %w", err)
			}
			chosen, err := selectInterface(listenIP, noPrompt, cmd.InOrStdin(), cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			baseURL := fmt.Sprintf("https://%s:%d", chosen.IP.String(), port)

			dataDir = expandHome(dataDir)
			dbPath = expandHome(dbPath)

			if _, err := os.Stat(dbPath); err == nil {
				return fmt.Errorf("state db already exists: %s", dbPath)
			} else if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("stat %s: %w", dbPath, err)
			}

			if err := os.MkdirAll(dataDir, 0700); err != nil {
				return fmt.Errorf("mkdir %s: %w", dataDir, err)
			}

			ctx := context.Background()
			database, err := db.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer database.Close()

			caObj, err := ca.Generate(filepath.Join(dataDir, "ca"))
			if err != nil {
				return fmt.Errorf("generate ca: %w", err)
			}

			priv, pubAuth, sshPub, err := ca.GeneratePeerKey()
			if err != nil {
				return fmt.Errorf("generate peer key: %w", err)
			}

			certBytes, serial, err := caObj.SignCert(ca.SignOptions{
				Pubkey:     sshPub,
				KeyID:      hostname,
				Principals: []string{hostname, "manager"},
			})
			if err != nil {
				return fmt.Errorf("sign cert: %w", err)
			}

			fingerprint := ssh.FingerprintSHA256(sshPub)

			if err := database.InsertPeerWithMode(ctx, hostname, serial, fingerprint, pubAuth, mode, targetUser); err != nil {
				return fmt.Errorf("insert peer: %w", err)
			}
			if err := database.EnsureGroup(ctx, "manager"); err != nil {
				return fmt.Errorf("ensure group manager: %w", err)
			}
			if err := database.SetPeerAllowedGroups(ctx, hostname, []string{"manager"}); err != nil {
				return fmt.Errorf("set allowed groups: %w", err)
			}

			selfDir := filepath.Join(dataDir, "self")
			if mode == db.ModeUser {
				if err := peerfiles.WriteUserSelfFiles(selfDir, peerfiles.UserPeerFiles{
					TargetUser: targetUser,
					PrivKey:    priv,
					CertPub:    certBytes,
					CAPub:      caObj.PublicKeyAuthorizedKey(),
					Principals: nil,
				}); err != nil {
					return fmt.Errorf("write self files: %w", err)
				}
			} else {
				caPubLine := strings.TrimRight(string(caObj.PublicKeyAuthorizedKey()), "\n")
				caKnownHostsEntry := "@cert-authority * " + caPubLine
				if err := peerfiles.WriteSelfFiles(selfDir, peerfiles.PeerFiles{
					Hostname:           hostname,
					PrivKey:            priv,
					CertPub:            certBytes,
					CAPub:              caObj.PublicKeyAuthorizedKey(),
					KRL:                nil,
					AuthPrincipalsRoot: nil,
					CAKnownHostsEntry:  caKnownHostsEntry,
				}); err != nil {
					return fmt.Errorf("write self files: %w", err)
				}
			}

			caPubParsed, _, _, _, err := ssh.ParseAuthorizedKey(caObj.PublicKeyAuthorizedKey())
			if err != nil {
				return fmt.Errorf("parse ca pubkey: %w", err)
			}
			caFingerprint := ssh.FingerprintSHA256(caPubParsed)

			if err := SaveBaseURL(dataDir, baseURL); err != nil {
				return fmt.Errorf("save base_url: %w", err)
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "certhold initialized\n")
			fmt.Fprintf(out, "  data-dir:       %s\n", dataDir)
			fmt.Fprintf(out, "  db:             %s\n", dbPath)
			fmt.Fprintf(out, "  mode:           %s\n", mode)
			if mode == db.ModeUser {
				fmt.Fprintf(out, "  target user:    %s\n", targetUser)
			}
			fmt.Fprintf(out, "  ca fingerprint: %s\n", caFingerprint)
			fmt.Fprintf(out, "  self files:     %s\n", selfDir)
			fmt.Fprintf(out, "  base url:       %s\n", baseURL)
			return nil
		},
	}
	cmd.Flags().String("hostname", "", "hostname to use as the certhold peer name (default: os.Hostname())")
	cmd.Flags().String("mode", db.ModeUser, "install mode for the manager's own self files: 'user' (default) or 'root'")
	cmd.Flags().String("user", "root", "Unix user that owns the manager's ~/.ssh files (defaults to the OS user running certhold when --mode=user; only meaningful in user mode)")
	cmd.Flags().String("listen-ip", "", "IPv4 of the interface peers will reach certhold on (skip prompt)")
	cmd.Flags().Int("port", 8443, "port the enroll endpoint listens on (used in the persisted base-url)")
	cmd.Flags().Bool("no-prompt", false, "fail instead of prompting; pass --listen-ip to choose explicitly")
	return cmd
}

func currentUsername() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	for _, env := range []string{"USER", "LOGNAME"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	return "root"
}

func expandHome(p string) string {
	if !strings.HasPrefix(p, "~/") && p != "~" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	if p == "~" {
		return home
	}
	return filepath.Join(home, p[2:])
}
