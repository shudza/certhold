package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

func newRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a peer",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.ErrOrStderr(), "not implemented")
			return errors.New("not implemented")
		},
	}
}
