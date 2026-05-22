package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

func newEnrollCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enroll",
		Short: "Enroll a new peer",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.ErrOrStderr(), "not implemented")
			return errors.New("not implemented")
		},
	}
}
