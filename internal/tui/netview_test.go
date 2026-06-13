package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func keyMsg(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// netModel disables real tick scheduling and, unless a probe is supplied,
// installs one that flags any unexpected probe execution.
func netModel(t *testing.T, probe ProbeFn) Model {
	t.Helper()
	m := newTestModel(nil)
	m.tick = func(int) tea.Cmd { return nil }
	if probe == nil {
		probe = func(ctx context.Context, host string) (time.Duration, error) {
			t.Errorf("unexpected probe of %q", host)
			return 0, nil
		}
	}
	m.probe = probe
	return m
}

// runCmd executes a command tree synchronously and collects the leaf messages.
func runCmd(cmd tea.Cmd) []tea.Msg {
	if cmd == nil {
		return nil
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		var out []tea.Msg
		for _, c := range batch {
			out = append(out, runCmd(c)...)
		}
		return out
	}
	return []tea.Msg{msg}
}

func pump(t *testing.T, m Model, msgs ...tea.Msg) Model {
	t.Helper()
	for _, msg := range msgs {
		nm, _ := m.Update(msg)
		m = nm.(Model)
	}
	return m
}

func lineWith(t *testing.T, v, substr string) string {
	t.Helper()
	for _, l := range strings.Split(v, "\n") {
		if strings.Contains(l, substr) {
			return l
		}
	}
	t.Fatalf("no line containing %q:\n%s", substr, v)
	return ""
}

func TestNetSweepProbesOnlyInboundPeers(t *testing.T) {
	var mu sync.Mutex
	var hosts []string
	rec := func(ctx context.Context, host string) (time.Duration, error) {
		mu.Lock()
		hosts = append(hosts, host)
		mu.Unlock()
		return 5 * time.Millisecond, nil
	}
	m := netModel(t, rec)
	m.now = func() time.Time { return time.Date(2026, 6, 10, 14, 3, 5, 0, time.UTC) }
	nm, cmd := m.Update(keyMsg("4"))
	m = nm.(Model)
	if m.view != viewNet {
		t.Fatalf("after '4' view = %v, want net", m.view)
	}
	if cmd == nil {
		t.Fatal("entering net view must start a sweep")
	}
	m = pump(t, m, runCmd(cmd)...)

	mu.Lock()
	got := strings.Join(hosts, ",")
	mu.Unlock()
	if got != "10.0.0.5,beta" {
		t.Fatalf("probed hosts = %q, want only inbound dial hosts %q", got, "10.0.0.5,beta")
	}
	v := m.View()
	if l := lineWith(t, v, "alpha"); !strings.Contains(l, "● up") || !strings.Contains(l, "5ms") || !strings.Contains(l, "14:03:05") {
		t.Fatalf("alpha row missing up/latency/last ok: %q", l)
	}
	if l := lineWith(t, v, "gamma"); !strings.Contains(l, "–") || strings.Contains(l, "up") {
		t.Fatalf("non-inbound gamma must stay not-probed: %q", l)
	}
}

func TestNetNoProbesWhileOtherViewsActive(t *testing.T) {
	probed := 0
	m := netModel(t, func(ctx context.Context, host string) (time.Duration, error) {
		probed++
		return 0, nil
	})
	for _, k := range []string{"2", "3", "1", "tab", "tab"} {
		nm, cmd := m.Update(keyMsg(k))
		m = nm.(Model)
		m = pump(t, m, runCmd(cmd)...)
	}
	if m.view == viewNet {
		t.Fatalf("test must end outside the net view, got %v", m.view)
	}
	if probed != 0 || m.probeGen != 0 {
		t.Fatalf("probed = %d gen = %d, want 0 and 0 while views 1-3 are active", probed, m.probeGen)
	}
	for _, k := range []string{"P", "p"} {
		nm, cmd := m.Update(keyMsg(k))
		m = nm.(Model)
		if cmd != nil {
			t.Fatalf("%q outside the net view must be a no-op", k)
		}
	}
	nm, cmd := m.Update(probeTickMsg{gen: m.probeGen})
	m = nm.(Model)
	if cmd != nil {
		t.Fatal("a tick arriving outside the net view must schedule nothing")
	}
	if probed != 0 {
		t.Fatalf("probed = %d after stray tick, want 0", probed)
	}
}

func TestNetResultOrderingStable(t *testing.T) {
	m := press(t, netModel(t, nil), "4")
	at := time.Date(2026, 6, 10, 14, 3, 5, 0, time.UTC)
	m = pump(t, m,
		probeResultMsg{gen: m.probeGen, name: "beta", latency: 42 * time.Millisecond, at: at},
		probeResultMsg{gen: m.probeGen, name: "alpha", latency: 7 * time.Millisecond, at: at},
	)
	v := m.View()
	ai, bi := strings.Index(v, "alpha"), strings.Index(v, "beta")
	if ai < 0 || bi < 0 || ai > bi {
		t.Fatalf("rows must follow data order regardless of arrival order (alpha@%d beta@%d):\n%s", ai, bi, v)
	}
	if l := lineWith(t, v, "alpha"); !strings.Contains(l, "7ms") {
		t.Fatalf("alpha latency wrong: %q", l)
	}
	if l := lineWith(t, v, "beta"); !strings.Contains(l, "42ms") {
		t.Fatalf("beta latency wrong: %q", l)
	}
}

func TestNetDownUpTransitionSetsLastOK(t *testing.T) {
	m := press(t, netModel(t, nil), "4")
	gen := m.probeGen
	m = pump(t, m, probeResultMsg{gen: gen, name: "alpha", err: errors.New("refused"), at: time.Date(2026, 6, 10, 9, 0, 0, 0, time.UTC)})
	l := lineWith(t, m.View(), "alpha")
	if !strings.Contains(l, "○ down") || strings.Contains(l, ":") {
		t.Fatalf("down-before-any-success row wrong (want no LAST OK): %q", l)
	}
	m = pump(t, m, probeResultMsg{gen: gen, name: "alpha", latency: 3 * time.Millisecond, at: time.Date(2026, 6, 10, 9, 30, 0, 0, time.UTC)})
	l = lineWith(t, m.View(), "alpha")
	if !strings.Contains(l, "● up") || !strings.Contains(l, "09:30:00") {
		t.Fatalf("down→up must set LAST OK: %q", l)
	}
	m = pump(t, m, probeResultMsg{gen: gen, name: "alpha", err: errors.New("timeout"), at: time.Date(2026, 6, 10, 9, 35, 0, 0, time.UTC)})
	l = lineWith(t, m.View(), "alpha")
	if !strings.Contains(l, "○ down") || !strings.Contains(l, "09:30:00") {
		t.Fatalf("up→down must keep the previous LAST OK: %q", l)
	}
}

func TestNetStaleGenerationResultsDropped(t *testing.T) {
	m := press(t, netModel(t, nil), "4")
	old := m.probeGen
	nm, cmd := m.Update(keyMsg("P"))
	m = nm.(Model)
	if cmd == nil || m.probeGen != old+1 {
		t.Fatalf("'P' must start a new sweep generation, gen %d → %d", old, m.probeGen)
	}
	m = pump(t, m, probeResultMsg{gen: old, name: "alpha", latency: time.Millisecond, at: time.Now()})
	if _, ok := m.probes["alpha"]; ok {
		t.Fatal("a stale-generation result must be discarded")
	}
	m = pump(t, m, probeResultMsg{gen: m.probeGen, name: "alpha", latency: time.Millisecond, at: time.Now()})
	if st, ok := m.probes["alpha"]; !ok || !st.up {
		t.Fatalf("current-generation result must apply, got %+v %v", st, ok)
	}
}

func TestNetPauseStopsSchedulingAndResumeRestarts(t *testing.T) {
	m := press(t, netModel(t, nil), "4")
	nm, cmd := m.Update(keyMsg("p"))
	m = nm.(Model)
	if !m.probePaused || cmd != nil {
		t.Fatalf("pause must set state and schedule nothing, paused=%v cmd=%v", m.probePaused, cmd)
	}
	v := m.View()
	if !strings.Contains(v, "probing paused") || !strings.Contains(v, "p resume") {
		t.Fatalf("footer must reflect paused state:\n%s", v)
	}
	nm, cmd = m.Update(probeTickMsg{gen: m.probeGen})
	m = nm.(Model)
	if cmd != nil {
		t.Fatal("pause must stop tick scheduling")
	}
	m = press(t, m, "1")
	nm, cmd = m.Update(keyMsg("4"))
	m = nm.(Model)
	if cmd != nil {
		t.Fatal("re-entering the net view while paused must not sweep")
	}
	nm, cmd = m.Update(keyMsg("P"))
	m = nm.(Model)
	if cmd == nil {
		t.Fatal("'P' must probe now even while paused")
	}
	nm, cmd = m.Update(keyMsg("p"))
	m = nm.(Model)
	if m.probePaused || cmd == nil {
		t.Fatalf("resume must clear state and sweep immediately, paused=%v cmd=%v", m.probePaused, cmd)
	}
	if v := m.View(); !strings.Contains(v, "p pause") || strings.Contains(v, "probing paused") {
		t.Fatalf("footer must reflect resumed state:\n%s", v)
	}
}

func TestNetTickAdvancesGenerationAndReschedules(t *testing.T) {
	var scheduled []int
	m := newTestModel(nil)
	m.probe = func(ctx context.Context, host string) (time.Duration, error) { return 0, nil }
	m.tick = func(gen int) tea.Cmd {
		scheduled = append(scheduled, gen)
		return nil
	}
	m = press(t, m, "4")
	if m.probeGen != 1 || len(scheduled) != 1 || scheduled[0] != 1 {
		t.Fatalf("entering net view: gen=%d scheduled=%v, want 1 and [1]", m.probeGen, scheduled)
	}
	nm, cmd := m.Update(probeTickMsg{gen: 1})
	m = nm.(Model)
	if cmd == nil || m.probeGen != 2 {
		t.Fatalf("a live tick must sweep and advance the generation, gen=%d", m.probeGen)
	}
	if len(scheduled) != 2 || scheduled[1] != 2 {
		t.Fatalf("tick must reschedule with the new generation, scheduled=%v", scheduled)
	}
	nm, cmd = m.Update(probeTickMsg{gen: 1})
	m = nm.(Model)
	if cmd != nil || len(scheduled) != 2 {
		t.Fatalf("a stale tick must be dropped, scheduled=%v", scheduled)
	}
}

func TestNetSweepConcurrencyCapped(t *testing.T) {
	d := fleetData{DBPath: "/tmp/state.db"}
	for i := 0; i < 9; i++ {
		d.Peers = append(d.Peers, peerRow{Name: fmt.Sprintf("p%d", i), DialHost: fmt.Sprintf("h%d", i), Inbound: true})
	}
	var mu sync.Mutex
	cur, peak := 0, 0
	entered := make(chan string, 16)
	release := make(chan struct{})
	m := NewModel(context.Background(), d, nil)
	m.tick = func(int) tea.Cmd { return nil }
	m.probe = func(ctx context.Context, host string) (time.Duration, error) {
		mu.Lock()
		cur++
		if cur > peak {
			peak = cur
		}
		mu.Unlock()
		entered <- host
		<-release
		mu.Lock()
		cur--
		mu.Unlock()
		return time.Millisecond, nil
	}
	nm, cmd := m.Update(keyMsg("4"))
	m = nm.(Model)
	batch, ok := cmd().(tea.BatchMsg)
	if !ok || len(batch) != 9 {
		t.Fatalf("sweep of 9 inbound peers must batch 9 probe cmds, got %T len %d", cmd(), len(batch))
	}
	results := make(chan tea.Msg, 9)
	var wg sync.WaitGroup
	for _, c := range batch {
		wg.Add(1)
		go func(c tea.Cmd) {
			defer wg.Done()
			results <- c()
		}(c)
	}
	for i := 0; i < probeConcurrency; i++ {
		<-entered
	}
	release <- struct{}{}
	<-entered
	close(release)
	wg.Wait()
	close(results)
	mu.Lock()
	gotPeak := peak
	mu.Unlock()
	if gotPeak != probeConcurrency {
		t.Fatalf("peak concurrent probes = %d, want exactly %d", gotPeak, probeConcurrency)
	}
	for msg := range results {
		m = pump(t, m, msg)
	}
	if got := strings.Count(m.View(), "● up"); got != 9 {
		t.Fatalf("up rows = %d, want 9:\n%s", got, m.View())
	}
}

func TestFmtLatency(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "<1ms"},
		{500 * time.Microsecond, "<1ms"},
		{5 * time.Millisecond, "5ms"},
		{9999 * time.Millisecond, "9999ms"},
		{10 * time.Second, "10.0s"},
		{12345 * time.Millisecond, "12.3s"},
	}
	for _, c := range cases {
		if got := fmtLatency(c.d); got != c.want {
			t.Errorf("fmtLatency(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

func TestFmtLastOK(t *testing.T) {
	now := time.Date(2026, 6, 13, 14, 0, 0, 0, time.Local)
	// Same calendar day → plain hh:mm:ss, no date marker.
	if got := fmtLastOK(time.Date(2026, 6, 13, 9, 30, 5, 0, time.Local), now); got != "09:30:05" {
		t.Errorf("same-day LAST OK = %q, want 09:30:05", got)
	}
	// Different day → mm-dd prefix so a >24h-old time is not read as today.
	got := fmtLastOK(time.Date(2026, 6, 10, 9, 30, 5, 0, time.Local), now)
	if !strings.Contains(got, "09:30:05") || !strings.Contains(got, "06-10") {
		t.Errorf("cross-day LAST OK = %q, want 06-10 09:30:05", got)
	}
}

func TestNetTabAndHeaderMarker(t *testing.T) {
	m := press(t, netModel(t, nil), "4")
	v := m.View()
	if !strings.Contains(v, "[4 net]") {
		t.Fatalf("net tab missing textual marker:\n%s", v)
	}
	for _, want := range []string{"PEER", "HOST", "STATUS", "LATENCY", "LAST OK", "P probe now", "p pause"} {
		if !strings.Contains(v, want) {
			t.Errorf("net view missing %q:\n%s", want, v)
		}
	}
}

func TestNetOverflowShowsScrollCue(t *testing.T) {
	d := testData()
	for i := 0; i < 10; i++ {
		d.Peers = append(d.Peers, peerRow{Name: fmt.Sprintf("peer%02d", i), DialHost: "host", Inbound: true})
	}
	m := NewModel(context.Background(), d, nil)
	m.tick = func(int) tea.Cmd { return nil }
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 10})
	m = press(t, nm.(Model), "4")
	total := len(d.Peers)
	if v := m.View(); !strings.Contains(v, fmt.Sprintf("1/%d", total)) || !strings.Contains(v, "▼") {
		t.Fatalf("overflowing net table missing scroll cue:\n%s", v)
	}
}

func TestNetScrollFollowsSelection(t *testing.T) {
	d := testData()
	for i := 0; i < 20; i++ {
		d.Peers = append(d.Peers, peerRow{Name: fmt.Sprintf("peer%02d", i), DialHost: "host", Inbound: true})
	}
	m := NewModel(context.Background(), d, nil)
	m.tick = func(int) tea.Cmd { return nil }
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 12})
	m = press(t, nm.(Model), "4")
	total := len(d.Peers)
	// j past the fold: a peer below the initial window must scroll into view and
	// the cue must advance off "1/total".
	for i := 0; i < total-1; i++ {
		m = press(t, m, "j")
	}
	v := m.View()
	last := d.Peers[total-1].Name
	if !strings.Contains(v, last) {
		t.Fatalf("scrolling to the bottom did not reveal %q:\n%s", last, v)
	}
	if !strings.Contains(v, fmt.Sprintf("%d/%d", total, total)) || !strings.Contains(v, "▲") {
		t.Fatalf("bottom scroll cue wrong (want %d/%d with ▲):\n%s", total, total, v)
	}
	if l := lineWith(t, v, last); !strings.HasPrefix(strings.TrimSpace(l), ">") {
		t.Fatalf("bottom peer %q is not the selected (cursor) row: %q", last, l)
	}
	// k all the way back to the top restores the 1/total ▼ cue.
	for i := 0; i < total-1; i++ {
		m = press(t, m, "k")
	}
	if v := m.View(); !strings.Contains(v, fmt.Sprintf("1/%d", total)) {
		t.Fatalf("scrolling back to top did not restore 1/%d cue:\n%s", total, v)
	}
}

func TestNetLayoutClamped(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.ANSI256)
	defer lipgloss.SetColorProfile(prev)

	sawANSI := false
	for _, size := range []tea.WindowSizeMsg{{Width: 120, Height: 30}, {Width: 80, Height: 24}, {Width: 60, Height: 16}} {
		d := wideData()
		d.Peers[0].DialHost = "an.extremely.long.peer.hostname.example.internal"
		m := NewModel(context.Background(), d, nil)
		m.tick = func(int) tea.Cmd { return nil }
		nm, _ := m.Update(size)
		m = press(t, nm.(Model), "4")
		m = pump(t, m,
			probeResultMsg{gen: m.probeGen, name: "alpha", latency: 1234 * time.Millisecond, at: time.Date(2026, 6, 10, 14, 3, 5, 0, time.UTC)},
			probeResultMsg{gen: m.probeGen, name: "beta", err: errors.New("connection refused"), at: time.Date(2026, 6, 10, 14, 3, 5, 0, time.UTC)},
		)
		v := m.View()
		if strings.Contains(v, "\x1b[") {
			sawANSI = true
		}
		for _, want := range []string{"● up", "○ down", "–", "1234ms"} {
			if !strings.Contains(v, want) {
				t.Errorf("%dx%d: net view missing %q:\n%s", size.Width, size.Height, want, v)
			}
		}
		lines := strings.Split(v, "\n")
		if len(lines) != size.Height {
			t.Fatalf("%dx%d: got %d lines", size.Width, size.Height, len(lines))
		}
		for _, l := range lines {
			if lw := lipgloss.Width(l); lw > size.Width {
				t.Fatalf("%dx%d: line overflows (%d > %d): %q", size.Width, size.Height, lw, size.Width, l)
			}
		}
	}
	if !sawANSI {
		t.Fatal("forced color profile produced no ANSI — overflow checks are vacuous")
	}
}
