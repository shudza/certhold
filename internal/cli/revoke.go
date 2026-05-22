package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/krl"
	"github.com/shudza/certhold/internal/sshpush"
)

// Injection points for testing. buildKRLFn defaults to krl.Build but tests
// substitute a stub so they need not depend on ssh-keygen. revokeDial opens
// an sshpush.Pusher to a host; tests inject an in-memory pusher.
var (
	buildKRLFn = krl.Build
	revokeDial func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error)
)

func defaultDial(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
	return sshpush.Dial(ctx, host, opts)
}

func newRevokeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke <name>",
		Short: "Revoke a peer and push a new KRL to all remaining peers",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRevoke(cmd, args[0])
		},
	}
	cmd.Flags().String("host", "", "unused; revoked peer itself is not pushed to")
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

	caDir := filepath.Join(dataDir, "ca")
	caPubPath := filepath.Join(caDir, "ca.pub")
	if _, err := ca.Load(caDir); err != nil {
		return fmt.Errorf("load ca: %w", err)
	}

	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	if err := d.SetPeerRevoked(ctx, name); err != nil {
		return fmt.Errorf("revoke peer %q: %w", name, err)
	}

	peers, err := d.ListPeers(ctx)
	if err != nil {
		return fmt.Errorf("list peers: %w", err)
	}

	var serials []uint64
	for _, p := range peers {
		if p.Revoked {
			serials = append(serials, p.Serial)
		}
	}

	krlBytes, err := buildKRLFn(ctx, caPubPath, serials)
	if err != nil {
		return fmt.Errorf("build KRL: %w", err)
	}

	version, err := d.NextKRLVersion(ctx)
	if err != nil {
		return fmt.Errorf("next krl version: %w", err)
	}

	selfDir := filepath.Join(dataDir, "self", "etc", "ssh")
	pushOpts := sshpush.Options{
		CertPath:       filepath.Join(selfDir, "peer_ed25519-cert.pub"),
		KeyPath:        filepath.Join(selfDir, "peer_ed25519"),
		KnownHostsPath: filepath.Join(selfDir, "ca_known_hosts"),
		User:           "root",
	}

	dial := revokeDial
	if dial == nil {
		dial = defaultDial
	}

	pushed := 0
	targets := 0
	errOut := cmd.ErrOrStderr()
	for _, p := range peers {
		if p.Revoked {
			continue
		}
		if p.Name == name {
			continue
		}
		targets++
		if err := pushOne(ctx, dial, p.Name, krlBytes, pushOpts); err != nil {
			fmt.Fprintf(errOut, "push %s: %v\n", p.Name, err)
			continue
		}
		if err := d.UpdatePeerLastKRL(ctx, p.Name, version); err != nil {
			fmt.Fprintf(errOut, "update last_krl_version for %s: %v\n", p.Name, err)
			continue
		}
		pushed++
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Revoked %s. KRL version %d pushed to %d/%d peers.\n", name, version, pushed, targets)
	return nil
}

func pushOne(ctx context.Context, dial func(context.Context, string, sshpush.Options) (sshpush.Pusher, error), host string, krlBytes []byte, opts sshpush.Options) error {
	if host == "" {
		return errors.New("empty host")
	}
	p, err := dial(ctx, host, opts)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer p.Close()
	if err := p.WriteFileAtomic(ctx, "/etc/ssh/krl", krlBytes, fs.FileMode(0644)); err != nil {
		return fmt.Errorf("write krl: %w", err)
	}
	if err := p.ReloadSSHD(ctx); err != nil {
		return fmt.Errorf("reload sshd: %w", err)
	}
	if err := p.VerifyHealth(ctx); err != nil {
		return fmt.Errorf("verify health: %w", err)
	}
	return nil
}
