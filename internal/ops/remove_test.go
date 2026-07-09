package ops

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/sshpush"
)

// noDialDeps builds Deps whose Dial fails the test if ever invoked, so a test
// can assert an op makes no SSH contact. CAUnlock/PeerPass likewise fail: remove
// must not unlock the CA or any passphrase.
func noDialDeps(t *testing.T, d *db.DB, events *[]Event) Deps {
	t.Helper()
	return Deps{
		DB: d,
		Dial: func(context.Context, string, sshpush.Options) (sshpush.Pusher, error) {
			t.Fatal("RemovePeer must not dial any peer")
			return nil, nil
		},
		CAUnlock: func() ([]byte, error) {
			t.Fatal("RemovePeer must not unlock the CA")
			return nil, nil
		},
		PeerPass: func() ([]byte, error) {
			t.Fatal("RemovePeer must not unlock a peer passphrase")
			return nil, nil
		},
		OnEvent: func(e Event) { *events = append(*events, e) },
	}
}

// fleetRevInt reads the numeric fleet revision so tests can assert a strict
// increase, not just inequality.
func fleetRevInt(t *testing.T, d *db.DB) int64 {
	t.Helper()
	v, err := d.FleetRev(context.Background())
	if err != nil {
		t.Fatalf("FleetRev: %v", err)
	}
	return v
}

func TestRemovePeerDeletesAndMakesNoContact(t *testing.T) {
	_, d := setupOpsEnv(t, "alpha", "beta")
	ctx := context.Background()
	revBefore := fleetRevInt(t, d)
	var events []Event
	deps := noDialDeps(t, d, &events)

	if err := RemovePeer(ctx, deps, "alpha"); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}

	if _, err := d.GetPeer(ctx, "alpha"); !errors.Is(err, db.ErrPeerNotFound) {
		t.Errorf("alpha still present after remove: err=%v", err)
	}
	if _, err := d.GetPeer(ctx, "beta"); err != nil {
		t.Errorf("beta should be untouched, got err=%v", err)
	}

	if len(events) != 1 || events[0].Type != EventInfo || events[0].Peer != "alpha" {
		t.Fatalf("events = %+v, want one EventInfo for alpha", events)
	}

	if revAfter := fleetRevInt(t, d); revAfter <= revBefore {
		t.Errorf("fleet_rev = %d after remove, want strictly greater than %d", revAfter, revBefore)
	}
}

func TestRemovePeerUnknownReturnsClearError(t *testing.T) {
	_, d := setupOpsEnv(t)
	ctx := context.Background()
	revBefore := fleetRevInt(t, d)
	var events []Event
	deps := noDialDeps(t, d, &events)

	err := RemovePeer(ctx, deps, "nosuch")
	if err == nil {
		t.Fatal("expected error for unknown peer")
	}
	if !errors.Is(err, db.ErrPeerNotFound) {
		t.Errorf("error does not wrap ErrPeerNotFound: %v", err)
	}
	if !strings.Contains(err.Error(), "nosuch") {
		t.Errorf("error should name the peer; got %q", err.Error())
	}
	if len(events) != 0 {
		t.Errorf("no event should be emitted on failure; got %+v", events)
	}
	if revAfter := fleetRevInt(t, d); revAfter != revBefore {
		t.Errorf("fleet_rev must be unchanged on failed remove; %d -> %d", revBefore, revAfter)
	}
}

func TestRemovePeerSelfGuardRefusalDoesNotBumpFleetRev(t *testing.T) {
	selfGuardSetHostname(t, "mgr")
	_, d := setupOpsEnv(t, "mgr", "alpha")
	revBefore := fleetRevInt(t, d)
	var events []Event
	deps := noDialDeps(t, d, &events)

	if err := RemovePeer(context.Background(), deps, "mgr"); err == nil {
		t.Fatal("expected self-guard refusal")
	}
	if revAfter := fleetRevInt(t, d); revAfter != revBefore {
		t.Errorf("fleet_rev must be unchanged on refused self remove; %d -> %d", revBefore, revAfter)
	}
}
