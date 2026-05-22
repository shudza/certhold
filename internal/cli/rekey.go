package cli

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/sshpush"
)

var rekeyDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
	return sshpush.Dial(ctx, host, opts)
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
			if hostname == "" {
				h, herr := os.Hostname()
				if herr != nil {
					return fmt.Errorf("hostname: %w", herr)
				}
				hostname = h
			}
			return runRekey(cmd, hostname)
		},
	}
	cmd.Flags().String("hostname", "", "certhold's own peer name (default: os.Hostname())")
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

	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	deps := rekeyDeps{
		DataDir:  dataDir,
		Hostname: hostname,
		DB:       d,
		Out:      cmd.OutOrStdout(),
		Err:      cmd.ErrOrStderr(),
		Dial:     rekeyDial,
	}
	return runRekeyCore(ctx, deps, nil)
}

func abortRekey(errOut interface {
	Write(p []byte) (n int, err error)
}, cause error, updated []string) error {
	fmt.Fprintf(errOut, "rekey aborted: %v\n", cause)
	if len(updated) > 0 {
		fmt.Fprintf(errOut, "peers already rotated to new CA (recovery may be required): %v\n", updated)
	}
	return cause
}

func writeFileAtomicLocal(path string, content []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("rename %s -> %s: %w", tmpName, path, err)
	}
	return nil
}
