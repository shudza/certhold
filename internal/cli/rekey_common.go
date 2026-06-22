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
	trustFlag, _ := cmd.Flags().GetBool(flagTrustNewHostKeys)
	return ops.Deps{
		DB:             d,
		DataDir:        dataDir,
		CAUnlock:       caUnlock.get,
		PeerPass:       peerUnlock.get,
		Dial:           ops.DialFn(dial),
		HostKeyConfirm: newHostKeyConfirm(trustNewHostKeys(trustFlag)),
		OnEvent:        opsEventPrinter(cmd.OutOrStdout(), cmd.ErrOrStderr()),
	}
}

// opsEventPrinter renders ops events to a command's stdout/stderr. It skips
// info/done events without a Msg: per-peer EventPeerDone is purely structural
// for some ops (the CLI historically printed nothing per pushed peer), and an
// empty Msg must not emit a blank line.
func opsEventPrinter(out, errOut io.Writer) func(ops.Event) {
	return func(e ops.Event) {
		switch e.Type {
		case ops.EventInfo, ops.EventPeerDone:
			if e.Msg != "" {
				fmt.Fprintf(out, "%s\n", e.Msg)
			}
		case ops.EventWarn:
			fmt.Fprintf(errOut, "%s\n", e.Msg)
		}
	}
}

func caKeyEncrypted(caDir string) (bool, error) {
	return ops.CAKeyEncrypted(caDir)
}
