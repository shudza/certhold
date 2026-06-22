package cli

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	defaultDataDir := filepath.Join(home, ".certhold")
	defaultDB := filepath.Join(defaultDataDir, "state.db")

	cmd := &cobra.Command{
		Use:          "certhold",
		Short:        "Certhold — homelab SSH access manager",
		Long:         "Certhold is a homelab SSH access manager. It runs an SSH certificate authority, signs peer certs, and pushes config to peers over SSH.",
		SilenceUsage: true,
	}

	cmd.PersistentFlags().String("db", defaultDB, "path to state database")
	cmd.PersistentFlags().String("data-dir", defaultDataDir, "path to data directory")
	cmd.PersistentFlags().Bool(flagTrustNewHostKeys, false, "accept unknown peer host keys without prompting (TOFU); also via CERTHOLD_TRUST_NEW_HOST_KEYS=1")

	cmd.AddCommand(
		newInitCmd(),
		newEnrollCmd(),
		newListCmd(),
		newTuiCmd(),
		newUpdateCmd(),
		newGroupCmd(),
		newRevokeCmd(),
		newRemoveCmd(),
		newRekeyCmd(),
		newServeCmd(),
		newInstallCmd(),
		newAddressCmd(),
		newMakeClientCmd(),
	)

	return cmd
}
