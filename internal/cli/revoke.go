package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/sshpush"
)

func defaultDial(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
	return sshpush.Dial(ctx, host, opts)
}

func newRevokeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke <name>",
		Short: "Revoke a peer via a partial CA rekey that excludes it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRevoke(cmd, args[0])
		},
	}
	cmd.Flags().String("hostname", "", "certhold's own peer name for the rekey-revoke (default: os.Hostname())")
	return cmd
}

func runRevoke(cmd *cobra.Command, name string) error {
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

	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	if _, err := d.GetPeer(ctx, name); err != nil {
		if errors.Is(err, db.ErrPeerNotFound) {
			return fmt.Errorf("revoke peer %q: %w", name, err)
		}
		return fmt.Errorf("get peer %q: %w", name, err)
	}

	if err := d.SetPeerRevoked(ctx, name); err != nil {
		return fmt.Errorf("revoke peer %q: %w", name, err)
	}

	caUnlock := newCAUnlocker()
	defer caUnlock.Zero()
	peerUnlock := newPeerUnlocker()
	defer peerUnlock.Zero()

	// Revocation rotates the CA, skipping the revoked peer, so its old (now
	// CA-retired) cert stops being accepted across the fleet.
	hostname, err := cmd.Flags().GetString("hostname")
	if err != nil {
		return fmt.Errorf("get hostname: %w", err)
	}
	if hostname == "" {
		h, herr := os.Hostname()
		if herr != nil {
			return fmt.Errorf("hostname: %w", herr)
		}
		hostname = h
	}
	deps := rekeyDeps{
		DataDir:    dataDir,
		Hostname:   hostname,
		DB:         d,
		Out:        cmd.OutOrStdout(),
		Err:        cmd.ErrOrStderr(),
		Dial:       rekeyDial,
		CAUnlock:   caUnlock.get,
		PeerPassFn: peerUnlock.get,
	}
	if deps.Dial == nil {
		deps.Dial = defaultDial
	}
	if err := runRekeyCore(ctx, deps, map[string]bool{name: true}); err != nil {
		return fmt.Errorf("rekey-revoke: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Revoked %s via CA rekey.\n", name)
	return nil
}
