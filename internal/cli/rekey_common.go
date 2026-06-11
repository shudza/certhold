package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/ops"
	"github.com/shudza/certhold/internal/sshpush"
)

// opsDeps assembles the ops.Deps for a mutation command, wiring progress
// events back to the command's stdout/stderr so output stays byte-identical
// to the historical inline implementations.
func opsDeps(cmd *cobra.Command, d *db.DB, dataDir string, caUnlock, peerUnlock *memoUnlocker, dial func(context.Context, string, sshpush.Options) (sshpush.Pusher, error)) ops.Deps {
	return ops.Deps{
		DB:       d,
		DataDir:  dataDir,
		CAUnlock: caUnlock.get,
		PeerPass: peerUnlock.get,
		Dial:     ops.DialFn(dial),
		OnEvent:  opsEventPrinter(cmd.OutOrStdout(), cmd.ErrOrStderr()),
	}
}

func opsEventPrinter(out, errOut io.Writer) func(ops.Event) {
	return func(e ops.Event) {
		switch e.Type {
		case ops.EventInfo, ops.EventPeerDone:
			fmt.Fprintf(out, "%s\n", e.Msg)
		case ops.EventWarn:
			fmt.Fprintf(errOut, "%s\n", e.Msg)
		}
	}
}

func caKeyEncrypted(caDir string) (bool, error) {
	return ops.CAKeyEncrypted(caDir)
}
