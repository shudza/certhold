package ops

import (
	"fmt"
	"os"
)

// osHostname is a seam so tests can pin the resolved self name.
var osHostname = os.Hostname

// guardNotSelfPeer refuses destructive peer operations aimed at the manager's
// own peer row (seeded once by init, named for the manager host). hostname is
// certhold's own peer name when the caller has one; empty means os.Hostname(),
// mirroring how Rekey resolves it. There is deliberately no escape hatch:
// deleting or altering the self row breaks rekey, revoke --rekey and all
// pushes, and nothing re-creates it short of manual DB surgery.
func guardNotSelfPeer(op, name, hostname string) error {
	if hostname == "" {
		h, err := osHostname()
		if err != nil {
			return fmt.Errorf("hostname: %w", err)
		}
		hostname = h
	}
	if name == hostname {
		return fmt.Errorf("refusing to %s certhold's own peer %q: this is the manager's self row; deleting or altering it breaks rekey, revoke --rekey and all pushes", op, name)
	}
	return nil
}
