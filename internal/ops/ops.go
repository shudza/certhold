// Package ops hosts certhold's mutation core — update/revoke/rekey logic
// extracted from the CLI so the TUI can drive the same operations. Progress
// is reported as structured Events; callers (CLI, TUI) decide how to render
// them.
package ops

import (
	"context"
	"fmt"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/sshpush"
)

type DialFn func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error)

type Deps struct {
	DB       *db.DB
	DataDir  string
	CAUnlock func() ([]byte, error)
	PeerPass func() ([]byte, error)
	Dial     DialFn
	OnEvent  func(Event) // nil = silent
}

type EventType int

const (
	EventInfo EventType = iota
	EventPeerStart
	EventPeerDone
	EventPeerFailed
	// EventWarn carries lines the CLI historically wrote to stderr (rekey
	// abort + straggler warnings); the stdout/stderr split could not be
	// expressed with EventInfo alone.
	EventWarn
)

// Event is one progress step of a mutation. Msg, when set, is the exact
// human-readable line the CLI historically printed (without the trailing
// newline); EventInfo/EventPeerDone lines went to stdout, EventWarn lines to
// stderr. EventPeerStart and EventPeerFailed produced no output.
type Event struct {
	Type EventType
	Peer string
	Msg  string
	Err  error
}

func (d Deps) emit(e Event) {
	if d.OnEvent != nil {
		d.OnEvent(e)
	}
}

func (d Deps) info(peer, msg string) {
	d.emit(Event{Type: EventInfo, Peer: peer, Msg: msg})
}

func (d Deps) warn(peer, msg string) {
	d.emit(Event{Type: EventWarn, Peer: peer, Msg: msg})
}

// ClientPeerNoticeMsg is the operator notice that a client-style (inbound=0)
// peer was not dialed: its DB-side changes land on its next pull.
func ClientPeerNoticeMsg(name string) string {
	return fmt.Sprintf("client peer %s: changes pending until 'certhold-cli refresh' runs on it", name)
}
