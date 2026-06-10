package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	installSystemctlFn  = func(args ...string) error { return exec.Command("systemctl", args...).Run() }
	installGeteuidFn    = os.Geteuid
	installExecutableFn = os.Executable
	installLookupUserFn = user.Lookup
	installUnitPath     = "/etc/systemd/system/certhold.service"
)

func newInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install certhold serve as a systemd system service",
		RunE:  runInstall,
	}
	cmd.Flags().String("addr", ":8443", "address for serve to listen on")
	cmd.Flags().String("tls-cert", "", "path to TLS certificate (optional; if unset, serve generates a self-signed cert)")
	cmd.Flags().String("tls-key", "", "path to TLS key (optional; if unset, serve generates a self-signed cert)")
	cmd.Flags().Bool("print", false, "print the rendered unit to stdout and exit (no root, no side effects)")
	return cmd
}

func runInstall(cmd *cobra.Command, args []string) error {
	unit, err := renderUnit(cmd)
	if err != nil {
		return err
	}

	doPrint, err := cmd.Flags().GetBool("print")
	if err != nil {
		return err
	}
	if doPrint {
		fmt.Fprint(cmd.OutOrStdout(), unit)
		return nil
	}

	if installGeteuidFn() != 0 {
		return errors.New("install must run as root: try 'sudo certhold install'")
	}

	out := cmd.OutOrStdout()

	existing, err := os.ReadFile(installUnitPath)
	changed := true
	switch {
	case err == nil:
		changed = string(existing) != unit
	case errors.Is(err, os.ErrNotExist):
		changed = true
	default:
		return fmt.Errorf("read %s: %w", installUnitPath, err)
	}

	if changed {
		if err := os.WriteFile(installUnitPath, []byte(unit), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", installUnitPath, err)
		}
	}

	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Changed files:")
	if changed {
		fmt.Fprintf(out, "  ~ %s   (wrote unit, 0644)\n", installUnitPath)
	} else {
		fmt.Fprintf(out, "  = %s   (unchanged)\n", installUnitPath)
	}

	if err := installSystemctlFn("daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if err := installSystemctlFn("enable", "--now", "certhold.service"); err != nil {
		return fmt.Errorf("systemctl enable --now certhold.service: %w", err)
	}

	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "certhold service installed and started (check: systemctl status certhold)")
	return nil
}

func renderUnit(cmd *cobra.Command) (string, error) {
	addr, err := cmd.Flags().GetString("addr")
	if err != nil {
		return "", err
	}
	tlsCert, err := cmd.Flags().GetString("tls-cert")
	if err != nil {
		return "", err
	}
	tlsKey, err := cmd.Flags().GetString("tls-key")
	if err != nil {
		return "", err
	}
	if (tlsCert == "") != (tlsKey == "") {
		return "", errors.New("--tls-cert and --tls-key must be provided together")
	}

	binary, err := installExecutableFn()
	if err != nil {
		return "", fmt.Errorf("resolve binary path: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(binary); err == nil {
		binary = resolved
	}

	targetUser := os.Getenv("SUDO_USER")
	if targetUser == "" {
		u, err := user.Current()
		if err != nil {
			return "", fmt.Errorf("resolve current user: %w", err)
		}
		targetUser = u.Username
	}

	dbPath, dataDir, err := resolveStatePaths(cmd, targetUser)
	if err != nil {
		return "", err
	}

	execStart := fmt.Sprintf("%s serve --addr %s --db %s --data-dir %s", binary, addr, dbPath, dataDir)
	if tlsCert != "" {
		absCert, err := filepath.Abs(expandHome(tlsCert))
		if err != nil {
			return "", fmt.Errorf("resolve tls-cert path: %w", err)
		}
		absKey, err := filepath.Abs(expandHome(tlsKey))
		if err != nil {
			return "", fmt.Errorf("resolve tls-key path: %w", err)
		}
		execStart += fmt.Sprintf(" --tls-cert %s --tls-key %s", absCert, absKey)
	}

	unit := "[Unit]\n" +
		"Description=Certhold SSH enrollment endpoint (certhold serve)\n" +
		"After=network-online.target\n" +
		"Wants=network-online.target\n" +
		"\n" +
		"[Service]\n" +
		"Type=simple\n" +
		fmt.Sprintf("User=%s\n", targetUser) +
		fmt.Sprintf("ExecStart=%s\n", execStart) +
		"Restart=on-failure\n" +
		"RestartSec=2\n" +
		"NoNewPrivileges=true\n" +
		"\n" +
		"[Install]\n" +
		"WantedBy=multi-user.target\n"

	return unit, nil
}

func resolveStatePaths(cmd *cobra.Command, targetUser string) (dbPath, dataDir string, err error) {
	pflags := cmd.Root().PersistentFlags()

	dbPath, err = pflags.GetString("db")
	if err != nil {
		return "", "", fmt.Errorf("get db: %w", err)
	}
	dataDir, err = pflags.GetString("data-dir")
	if err != nil {
		return "", "", fmt.Errorf("get data-dir: %w", err)
	}

	dbChanged := pflags.Changed("db")
	dataDirChanged := pflags.Changed("data-dir")

	var home string
	if !dbChanged || !dataDirChanged {
		u, err := installLookupUserFn(targetUser)
		if err != nil {
			return "", "", fmt.Errorf("lookup user %q: %w", targetUser, err)
		}
		home = u.HomeDir
	}

	if dbChanged {
		dbPath, err = filepath.Abs(expandHome(dbPath))
		if err != nil {
			return "", "", fmt.Errorf("resolve db path: %w", err)
		}
	} else {
		dbPath = filepath.Join(home, ".certhold", "state.db")
	}

	if dataDirChanged {
		dataDir, err = filepath.Abs(expandHome(dataDir))
		if err != nil {
			return "", "", fmt.Errorf("resolve data-dir path: %w", err)
		}
	} else {
		dataDir = filepath.Join(home, ".certhold")
	}

	return dbPath, dataDir, nil
}
