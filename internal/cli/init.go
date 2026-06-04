package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/passphrase"
	"github.com/shudza/certhold/internal/peerfiles"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

const noPassphraseBanner = `================================================================
  WARNING: --no-passphrase
================================================================
  The CA private key and certhold's own peer key will be written
  to disk UNENCRYPTED in <data-dir>. Anyone with read access to
  these files obtains, immediately:

    1. The CA key — can mint a manager-principal cert for any
       attacker-chosen pubkey, giving root on every enrolled
       peer.
    2. The manager peer key and its cert — gives root on every
       enrolled peer directly, no signing required.

  These two keys are the entire trust root of certhold. Theft of
  either is unrecoverable except by a full CA rekey AND re-enrolling
  every peer from scratch.

  The default (passphrase-protected) is strongly recommended.
  Only proceed if <data-dir> is on storage you already protect
  by other means (e.g. LUKS with a passphrase you trust, ephemeral
  CI/test environment, etc.).
================================================================
Type 'yes' to confirm --no-passphrase: `

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
			targetUser, err := cmd.Flags().GetString("user")
			if err != nil {
				return fmt.Errorf("get user: %w", err)
			}
			if !cmd.Flags().Changed("user") {
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

			noPassphrase, err := cmd.Flags().GetBool("no-passphrase")
			if err != nil {
				return fmt.Errorf("get no-passphrase: %w", err)
			}
			separate, err := cmd.Flags().GetBool("separate-passphrases")
			if err != nil {
				return fmt.Errorf("get separate-passphrases: %w", err)
			}

			var caPass, peerPass []byte
			defer func() {
				passphrase.Zero(caPass)
				passphrase.Zero(peerPass)
			}()
			if noPassphrase {
				fmt.Fprint(cmd.ErrOrStderr(), noPassphraseBanner)
				reader := bufio.NewReader(cmd.InOrStdin())
				line, _ := reader.ReadString('\n')
				if strings.TrimSpace(line) != "yes" {
					return errors.New("--no-passphrase not confirmed")
				}
			} else if separate {
				caPass, err = passphrase.PromptConfirm("CA passphrase: ", envCAPassphrase)
				if err != nil {
					return fmt.Errorf("read ca passphrase: %w", err)
				}
				peerPass, err = passphrase.PromptConfirm("Manager peer passphrase: ", envPeerPassphrase)
				if err != nil {
					return fmt.Errorf("read manager peer passphrase: %w", err)
				}
			} else {
				caPass, err = passphrase.PromptConfirm("Passphrase for CA and manager key: ", envCAPassphrase)
				if err != nil {
					return fmt.Errorf("read passphrase: %w", err)
				}
				peerPass = caPass
			}

			ctx := context.Background()
			database, err := db.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer database.Close()

			instanceKey, err := EnsureInstanceKey(ctx, database)
			if err != nil {
				return fmt.Errorf("ensure instance key: %w", err)
			}

			caObj, err := ca.GenerateWithPassphrase(filepath.Join(dataDir, "ca"), caPass)
			if err != nil {
				return fmt.Errorf("generate ca: %w", err)
			}

			priv, pubAuth, sshPub, err := ca.GeneratePeerKeyWithPassphrase(peerPass)
			if err != nil {
				return fmt.Errorf("generate peer key: %w", err)
			}
			defer zeroBytes(priv)

			certBytes, serial, err := caObj.SignCert(ca.SignOptions{
				Pubkey:     sshPub,
				KeyID:      hostname,
				Principals: []string{hostname, peerfiles.ManagerPrincipal},
			})
			if err != nil {
				return fmt.Errorf("sign cert: %w", err)
			}

			fingerprint := ssh.FingerprintSHA256(sshPub)

			if err := database.InsertPeer(ctx, hostname, serial, fingerprint, pubAuth, targetUser); err != nil {
				return fmt.Errorf("insert peer: %w", err)
			}
			if err := database.EnsureGroup(ctx, peerfiles.ManagerPrincipal); err != nil {
				return fmt.Errorf("ensure group manager: %w", err)
			}
			if err := database.SetPeerAllowedGroups(ctx, hostname, []string{peerfiles.ManagerPrincipal}); err != nil {
				return fmt.Errorf("set allowed groups: %w", err)
			}

			selfDir := filepath.Join(dataDir, "self")
			if err := peerfiles.WriteUserSelfFiles(selfDir, peerfiles.UserPeerFiles{
				TargetUser:  targetUser,
				PrivKey:     priv,
				CertPub:     certBytes,
				CAPub:       caObj.PublicKeyAuthorizedKey(),
				Principals:  nil,
				InstanceKey: instanceKey,
			}); err != nil {
				return fmt.Errorf("write self files: %w", err)
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
			fmt.Fprintf(out, "  target user:    %s\n", targetUser)
			fmt.Fprintf(out, "  ca fingerprint: %s\n", caFingerprint)
			fmt.Fprintf(out, "  self files:     %s\n", selfDir)
			fmt.Fprintf(out, "  base url:       %s\n", baseURL)
			return nil
		},
	}
	cmd.Flags().String("hostname", "", "hostname to use as the certhold peer name (default: os.Hostname())")
	cmd.Flags().String("user", "root", "Unix user that owns the manager's ~/.ssh files (defaults to the OS user running certhold; --user root targets /root/.ssh)")
	cmd.Flags().String("listen-ip", "", "IPv4 of the interface peers will reach certhold on (skip prompt)")
	cmd.Flags().Int("port", 8443, "port the enroll endpoint listens on (used in the persisted base-url)")
	cmd.Flags().Bool("no-prompt", false, "fail instead of prompting; pass --listen-ip to choose explicitly")
	cmd.Flags().Bool("no-passphrase", false, "write the CA and manager keys UNENCRYPTED (requires typing 'yes'); not recommended")
	cmd.Flags().Bool("separate-passphrases", false, "prompt for distinct CA and manager-key passphrases instead of sharing one")
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
