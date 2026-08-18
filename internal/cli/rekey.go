package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/ops"
	"github.com/shudza/certhold/internal/passphrase"
	"github.com/shudza/certhold/internal/sshpush"
)

var rekeyDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
	return sshpush.Dial(ctx, host, opts)
}

// promptNewCAPassphrase obtains a fresh CA passphrase (with confirmation) for
// --rotate-passphrase. It is a package var so tests can drive a new passphrase
// distinct from the old one without a tty; production wiring prompts twice via
// passphrase.PromptConfirm. The empty envVar is deliberate: reusing
// CERTHOLD_CA_PASSPHRASE here would make the new passphrase indistinguishable
// from the old one that deps.CAUnlock already reads.
var promptNewCAPassphrase = func() ([]byte, error) {
	return passphrase.PromptConfirm("New CA passphrase: ", "")
}

func newRekeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rekey",
		Short: "Rotate the CA: reissue certs for all peers, push atomically, retire old CA",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			hostname, err := cmd.Flags().GetString("hostname")
			if err != nil {
				return fmt.Errorf("get hostname: %w", err)
			}
			return runRekey(cmd, hostname)
		},
	}
	cmd.Flags().String("hostname", "", "certhold's own peer name (default: the name recorded at init)")
	cmd.Flags().Bool("rotate-passphrase", false, "prompt for a fresh CA passphrase for the new key instead of reusing the current one")
	return cmd
}

func runRekey(cmd *cobra.Command, hostname string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
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

	rotate, err := cmd.Flags().GetBool("rotate-passphrase")
	if err != nil {
		return fmt.Errorf("get rotate-passphrase: %w", err)
	}

	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	caUnlock := newCAUnlocker()
	defer caUnlock.Zero()
	peerUnlock := newPeerUnlocker()
	defer peerUnlock.Zero()

	deps := opsDeps(cmd, d, dataDir, caUnlock, peerUnlock, rekeyDial)
	return ops.Rekey(ctx, deps, ops.RekeyOptions{
		Hostname:         hostname,
		RotatePassphrase: rotate,
		NewPassphrase:    func() ([]byte, error) { return promptNewCAPassphrase() },
	})
}
