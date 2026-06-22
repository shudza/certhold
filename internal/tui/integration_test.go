package tui

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/ops"
)

// frameSink is the in-memory tea.WithOutput target. The real program's renderer
// writes full alt-screen repaints here; the sink accumulates them and signals a
// channel on every write so a driver can wait for a frame to contain a marker
// without sleeping. snapshot returns the ANSI-stripped accumulated output, whose
// tail is the latest fully-rendered frame.
type frameSink struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	wake chan struct{}
}

func newFrameSink() *frameSink { return &frameSink{wake: make(chan struct{}, 1)} }

func (s *frameSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	n, err := s.buf.Write(p)
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return n, err
}

func (s *frameSink) snapshot() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ansi.Strip(s.buf.String())
}

// integrationCA seeds an encrypted-CA db with three inbound peers (alpha in
// infra/db, beta in infra, gamma in infra) plus the "infra"/"db"/"web" groups,
// so the run can enroll, edit membership, and batch-revoke against real ops
// paths. certhold's own peer "alpha" anchors the rekey self-files. Returns the
// dataDir, db, dbPath and the CA passphrase the run must type.
func integrationEnv(t *testing.T) (string, *db.DB, string, string) {
	t.Helper()
	dataDir := t.TempDir()
	const pass = "integr8"
	if _, err := ca.GenerateWithPassphrase(filepath.Join(dataDir, "ca"), []byte(pass)); err != nil {
		t.Fatalf("GenerateWithPassphrase: %v", err)
	}
	dbPath := filepath.Join(dataDir, "state.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	ctx := context.Background()
	if err := d.InsertCAVersion(ctx, 1); err != nil {
		t.Fatalf("InsertCAVersion: %v", err)
	}
	if err := d.SetActiveCAVersion(ctx, 1); err != nil {
		t.Fatalf("SetActiveCAVersion: %v", err)
	}
	if _, err := ops.EnsureInstanceKey(ctx, d); err != nil {
		t.Fatalf("EnsureInstanceKey: %v", err)
	}
	for _, g := range []string{"infra", "db", "web"} {
		if err := d.EnsureGroup(ctx, g); err != nil {
			t.Fatalf("EnsureGroup %s: %v", g, err)
		}
	}
	for _, name := range []string{"alpha", "beta", "gamma"} {
		_, pubAuth, sshPub, err := ca.GeneratePeerKey()
		if err != nil {
			t.Fatalf("GeneratePeerKey %s: %v", name, err)
		}
		if err := d.InsertPeer(ctx, name, 100, ssh.FingerprintSHA256(sshPub), pubAuth, "root", true, ""); err != nil {
			t.Fatalf("InsertPeer %s: %v", name, err)
		}
		if err := d.SetPeerGroups(ctx, name, []string{"infra"}); err != nil {
			t.Fatalf("SetPeerGroups %s: %v", name, err)
		}
		if err := d.SetPeerAllowedGroups(ctx, name, []string{"infra"}); err != nil {
			t.Fatalf("SetPeerAllowedGroups %s: %v", name, err)
		}
	}
	if err := d.SetPeerGroups(ctx, "alpha", []string{"infra", "db"}); err != nil {
		t.Fatalf("SetPeerGroups alpha: %v", err)
	}
	if err := d.BumpFleetRev(ctx); err != nil {
		t.Fatalf("BumpFleetRev: %v", err)
	}
	return dataDir, d, dbPath, pass
}

// TestIntegrationFullSurface drives a REAL tea.Program through the whole mutating
// surface — enroll → group membership → batch-revoke → status — over in-memory
// input/output (no tty), with a real temp sqlite, a fake pusher DialFn, and the
// func-literal passphrase typed through the masked modal. It asserts on rendered
// frames and on the final db state. Synchronization is by frame-content (the
// renderer signals every write); there are no sleeps.
func TestIntegrationFullSurface(t *testing.T) {
	dataDir, d, dbPath, pass := integrationEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	action := ActionDeps{
		Hostname: "alpha",
		BuildDeps: func(onEvent func(ops.Event), caUnlock, peerPass func() ([]byte, error)) ops.Deps {
			return ops.Deps{
				DB:       d,
				DataDir:  dataDir,
				CAUnlock: caUnlock,
				PeerPass: peerPass,
				Dial:     fakeDial,
				OnEvent:  onEvent,
			}
		},
	}

	reload := func(ctx context.Context) (fleetData, error) { return load(ctx, d, dbPath) }
	data, err := reload(ctx)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	m := NewModel(ctx, data, reload).withAction(action)
	defer m.pass.close()
	defer m.peerPass.Close()

	in, sink := newProgramInput(), newFrameSink()
	p := tea.NewProgram(m, tea.WithContext(ctx), tea.WithInput(in), tea.WithOutput(sink))

	done := make(chan error, 1)
	go func() {
		_, err := p.Run()
		done <- err
	}()

	// A WindowSizeMsg gives the frame a known geometry so the table renders.
	p.Send(tea.WindowSizeMsg{Width: 120, Height: 40})

	// waitFrame blocks until the CURRENT rendered frame (the latest full
	// alt-screen repaint, not the cumulative history) contains marker, so a stale
	// marker from an earlier step cannot satisfy a later barrier. Synchronizes on
	// the renderer's per-write wake; no sleeps.
	waitFrame := func(marker string) {
		t.Helper()
		deadline := time.After(10 * time.Second)
		for {
			if strings.Contains(lastFrame(sink.snapshot()), marker) {
				return
			}
			select {
			case <-sink.wake:
			case <-deadline:
				t.Fatalf("frame never showed %q; last frame:\n%s", marker, lastFrame(sink.snapshot()))
			}
		}
	}
	// typeText sends each rune as a key; the program processes them in order.
	typeText := func(s string) {
		for _, r := range s {
			p.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		}
	}
	key := func(s string) { p.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}) }
	special := func(k tea.KeyType) { p.Send(tea.KeyMsg{Type: k}) }
	repeat := func(n int, s string) {
		for i := 0; i < n; i++ {
			key(s)
		}
	}

	waitFrame("certhold")
	waitFrame("alpha")

	// --- 1. enroll a new peer "edge1" via the e form -----------------------
	key("e")
	waitFrame("enroll peer")
	typeText("edge1")
	// tab from name → groups → allowed → user → address → client → submit.
	// On the groups picker, toggle "db" into the new peer's membership.
	special(tea.KeyTab) // → groups picker
	waitFrame("groups (space toggle")
	key(" ")            // toggle the cursor's first group (db, after sort)
	special(tea.KeyTab) // → allowed
	special(tea.KeyTab) // → user
	special(tea.KeyTab) // → address
	special(tea.KeyTab) // → client
	special(tea.KeyTab) // → submit
	special(tea.KeyEnter)
	// MintEnroll prompts for the CA passphrase through the masked modal.
	waitFrame("CA passphrase")
	typeText(pass)
	special(tea.KeyEnter)
	// On success the progress modal yields to the result screen with the
	// one-liner; assert the curl line rendered and the token is not the raw
	// pull_token (the result screen shows the enroll token only).
	waitFrame("curl -kfsSL")
	if got := waitDBPeer(t, d, "edge1"); !got {
		t.Fatal("edge1 not in db after enroll")
	}
	special(tea.KeyEsc) // dismiss result screen → back to peers table
	// Sync on the post-enroll RELOAD, not the result modal (whose title also
	// contains "edge1"): the peers tab count rises to 4 only once the reload
	// triggered by the enroll's completion has landed, so the subsequent
	// membership picker is built from data that includes edge1.
	waitFrame("1 peers (4)")

	// --- 2. add edge1 to the "web" group via the groups view 'm' picker -----
	key("2")
	waitFrame("2 groups (3)")
	// Navigate deterministically to the "web" group row by its known db order
	// (load preserves db order; the groups view does not re-sort). Reset to the
	// top first with up-presses (clamped no-op at row 0) so the start row is
	// known regardless of any prior selection.
	repeat(8, "up")
	gWeb := groupRowIndex(t, d, "web")
	repeat(gWeb, "j")
	key("m")
	waitFrame("members of web")
	// The picker lists non-revoked peers sorted: alpha, beta, edge1, gamma.
	// Cursor starts at alpha (0); move to edge1 (index 2) and toggle it on.
	repeat(2, "j")
	key(" ")
	// Wait for the picker to reflect edge1 checked before submitting, so the
	// toggle is observed-applied (not racing the submit under load).
	waitFrame("[x] edge1")
	special(tea.KeyEnter)
	// membership UpdatePeer re-signs (CA cached, no prompt) and pushes (fake).
	waitFrame("done")
	special(tea.KeyEsc)
	if g := peerGroups(t, d, "edge1"); !slices.Contains(g, "web") {
		t.Fatalf("edge1 groups after membership = %v, want to contain web", g)
	}

	// --- 3. batch-revoke beta + gamma from the peers view -------------------
	// Default revoke clears certhold off each (reachable, fake-dialled) peer and
	// hard-deletes its row; it does not rotate the CA or bump fleet_rev.
	key("1")
	waitFrame("1 peers")
	// Peers table is in db order: alpha(0), beta(1), edge1(2), gamma(3). Reset to
	// the top, then mark beta and gamma with space (marks are keyed by name, so
	// the space toggles the row under the cursor).
	repeat(8, "up")
	key("j")       // → beta
	key(" ")       // mark beta
	repeat(2, "j") // → gamma (past edge1)
	key(" ")       // mark gamma
	waitFrame("2 marked")
	key("x")
	waitFrame("Clear certhold off 2 peers")
	key("y")
	// Each revoke clears the peer over the fake dial, reusing the cached manager
	// peer-key passphrase (no second prompt).
	waitFrame("2 ok, 0 failed")
	waitFrame("done")
	special(tea.KeyEsc)

	// --- 4. status view (3) renders and the revoked peers are gone ----------
	key("3")
	waitFrame("FLEET")
	// beta and gamma were cleared+deleted; their rows must be gone, while the
	// manager peer alpha survives.
	if !waitDBDeleted(t, d, "beta") || !waitDBDeleted(t, d, "gamma") {
		t.Fatal("db: beta/gamma rows not deleted after default batch revoke")
	}
	if _, err := d.GetPeer(ctx, "alpha"); err != nil {
		t.Fatalf("db: manager peer alpha must survive a peer revoke: %v", err)
	}

	// quit cleanly and confirm a clean program exit (no deadlock).
	key("q")
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("program exited with error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("program did not exit after q — possible deadlock")
	}
}

// --- driver helpers --------------------------------------------------------

// programInput is a blocking in-memory reader the program's input loop reads
// from. The driver never writes raw bytes (it uses p.Send for key messages), so
// this just blocks until the program's context is canceled, keeping the input
// goroutine parked without an EOF that would tear the program down early.
type programInput struct {
	ch chan []byte
}

func newProgramInput() *programInput { return &programInput{ch: make(chan []byte)} }

func (r *programInput) Read(p []byte) (int, error) {
	b, ok := <-r.ch
	if !ok {
		return 0, context.Canceled
	}
	return copy(p, b), nil
}

func lastFrame(s string) string {
	// The alt-screen renderer repaints from the top each frame; the header line
	// always begins at column 0 with "certhold ...". Anchor on a line-start
	// "certhold" (not the mid-line "certhold.home.lan" that appears inside an
	// enroll one-liner), so lastFrame returns exactly the latest full frame.
	if strings.HasPrefix(s, "certhold ") {
		if i := strings.LastIndex(s, "\ncerthold "); i >= 0 {
			return s[i+1:]
		}
		return s
	}
	if i := strings.LastIndex(s, "\ncerthold "); i >= 0 {
		return s[i+1:]
	}
	return s
}

func frameLine(frame, substr string) string {
	for _, l := range strings.Split(frame, "\n") {
		if strings.Contains(l, substr) {
			return l
		}
	}
	return ""
}

func lineWithDigit(frame, label string, n int64) string {
	for _, l := range strings.Split(frame, "\n") {
		if strings.Contains(l, label) && strings.Contains(l, strconv.FormatInt(n, 10)) {
			return l
		}
	}
	return ""
}

func groupRowIndex(t *testing.T, d *db.DB, name string) int {
	t.Helper()
	groups, err := d.ListGroupsWithPeerCount(context.Background())
	if err != nil {
		t.Fatalf("ListGroupsWithPeerCount: %v", err)
	}
	var names []string
	for _, g := range groups {
		names = append(names, g.Name)
	}
	// load() preserves db order; the groups view does not re-sort rows.
	for i, n := range names {
		if n == name {
			return i
		}
	}
	t.Fatalf("group %q not found in %v", name, names)
	return 0
}

// waitDBPeer / waitDBDeleted poll the db (the action's reload is async) for the
// expected committed state, bounded so a failure surfaces instead of hanging.
func waitDBPeer(t *testing.T, d *db.DB, name string) bool {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		if _, err := d.GetPeer(context.Background(), name); err == nil {
			return true
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			return false
		}
	}
}

func waitDBDeleted(t *testing.T, d *db.DB, name string) bool {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		if _, err := d.GetPeer(context.Background(), name); errors.Is(err, db.ErrPeerNotFound) {
			return true
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			return false
		}
	}
}
