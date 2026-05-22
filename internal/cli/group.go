package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

func newGroupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "group",
		Short: "Manage groups and group memberships",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.ErrOrStderr(), "not implemented")
			return errors.New("not implemented")
		},
	}
}
