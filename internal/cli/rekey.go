package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

func newRekeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rekey",
		Short: "Rotate a peer's key and certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.ErrOrStderr(), "not implemented")
			return errors.New("not implemented")
		},
	}
}
