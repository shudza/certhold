package ops

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/sshpush"
)

var errUnknownHost = errors.New("knownhosts: key is unknown")

// confirmDialer simulates an sshpush.Dial against a peer whose host key is
// UNKNOWN: it drives opts.HostKeyConfirmFn exactly like the real Dial — accept
// (true,nil) -> dial succeeds, reject (false,nil) -> unknown-host error, and a
// nil confirm fn -> unknown-host error (today's strict behavior). It records
// each dialed host so tests can assert the push proceeded.
type confirmDialer struct {
	dialer   *fakeDialer
	hostKey  ssh.PublicKey
	confirmd []string
}

func (c *confirmDialer) dial(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
	if opts.HostKeyConfirmFn == nil {
		return nil, errUnknownHost
	}
	ok, err := opts.HostKeyConfirmFn(host, c.hostKey)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errUnknownHost
	}
	c.confirmd = append(c.confirmd, host)
	return c.dialer.dial(ctx, host, opts)
}

// testHostKey returns a fresh ssh.PublicKey for confirm-fn fingerprinting.
func testHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen host key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("new ssh pub: %v", err)
	}
	return sshPub
}

func TestDialPushHostKeyConfirmHealsUnknownHost(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peer1")
	ctx := context.Background()

	cd := &confirmDialer{
		dialer:  &fakeDialer{readData: map[string][]byte{"/root/.ssh/authorized_keys": opsCALine(t, dataDir, "manager", "infra")}},
		hostKey: testHostKey(t),
	}
	var events []Event
	var confirmCalls int
	deps := Deps{
		DB:      d,
		DataDir: dataDir,
		Dial:    cd.dial,
		HostKeyConfirm: func(host, fp, keyType string) (bool, error) {
			confirmCalls++
			if !strings.HasPrefix(fp, "SHA256:") {
				t.Errorf("fingerprint = %q, want SHA256: prefix", fp)
			}
			if keyType == "" {
				t.Errorf("key type must be non-empty")
			}
			return true, nil
		},
		OnEvent: func(e Event) { events = append(events, e) },
	}

	// A real push path (group allow) must proceed once the unknown host is
	// confirmed. peer1 is inbound + reachable by setupOpsEnv default.
	if err := SetPeerAllowedGroups(ctx, deps, "peer1", []string{"infra"}, "", ""); err != nil {
		t.Fatalf("SetPeerAllowedGroups: %v", err)
	}
	if confirmCalls != 1 {
		t.Fatalf("HostKeyConfirm called %d times, want 1", confirmCalls)
	}
	if len(cd.confirmd) != 1 {
		t.Fatalf("dial did not proceed after confirm: %v", cd.confirmd)
	}
	var sawLearned bool
	for _, e := range events {
		if e.Type == EventInfo && strings.Contains(e.Msg, "learned host key") {
			sawLearned = true
		}
	}
	if !sawLearned {
		t.Fatalf("expected a learned-host-key notice, events: %+v", events)
	}
}

func TestDialPushHostKeyConfirmRejectSurfacesError(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peer1")
	ctx := context.Background()

	cd := &confirmDialer{dialer: &fakeDialer{}, hostKey: testHostKey(t)}
	deps := Deps{
		DB:      d,
		DataDir: dataDir,
		Dial:    cd.dial,
		HostKeyConfirm: func(host, fp, keyType string) (bool, error) {
			return false, nil
		},
	}

	err := SetPeerAllowedGroups(ctx, deps, "peer1", []string{"infra"}, "", "")
	if err == nil {
		t.Fatal("rejecting the unknown host must surface a dial error")
	}
	if !errors.Is(err, errUnknownHost) {
		t.Fatalf("error = %v, want it to wrap the unknown-host error", err)
	}
	if len(cd.confirmd) != 0 {
		t.Fatalf("a rejected host must not be dialed for push: %v", cd.confirmd)
	}
}

func TestDialPushNilConfirmUnchangedUnknownStillFails(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peer1")
	ctx := context.Background()

	cd := &confirmDialer{dialer: &fakeDialer{}, hostKey: testHostKey(t)}
	deps := Deps{
		DB:      d,
		DataDir: dataDir,
		Dial:    cd.dial,
		// HostKeyConfirm intentionally nil: no confirm available.
	}

	err := SetPeerAllowedGroups(ctx, deps, "peer1", []string{"infra"}, "", "")
	if err == nil {
		t.Fatal("with no confirm fn, an unknown host must still fail")
	}
	if !errors.Is(err, errUnknownHost) {
		t.Fatalf("error = %v, want it to wrap the unknown-host error", err)
	}
	if len(cd.confirmd) != 0 {
		t.Fatalf("nothing should be dialed for push: %v", cd.confirmd)
	}
}
