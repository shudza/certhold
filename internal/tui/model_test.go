package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func testData() fleetData {
	return fleetData{
		DBPath:         "/tmp/state.db",
		FleetRev:       7,
		CAVersion:      2,
		CAVersionKnown: true,
		Peers: []peerRow{
			{
				Name: "alpha", DialHost: "10.0.0.5", TargetUser: "alice",
				Fingerprint: "SHA256:fp-alpha", Serial: 11, Inbound: true,
				HasPullToken: true, CreatedAt: time.Date(2026, 1, 2, 15, 4, 0, 0, time.UTC),
				Groups: []string{"infra"}, Allowed: []string{"ops"},
				Expires: certExpiry{state: certAt, until: time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)},
			},
			{
				Name: "beta", DialHost: "beta", Serial: 12, Inbound: true, Revoked: true,
				Expires: certExpiry{state: certNone},
			},
			{
				Name: "gamma", DialHost: "gw.lan", Serial: 13, Inbound: false,
				Expires: certExpiry{state: certForever},
			},
		},
		Groups: []groupRow{
			{Name: "infra", PeerCount: 2, Members: []string{"alpha", "beta"}, AllowedBy: []string{"gamma"}},
			{Name: "ops", PeerCount: 0, AllowedBy: []string{"alpha"}},
		},
	}
}

func newTestModel(reload reloader) Model {
	if reload == nil {
		reload = func(ctx context.Context) (fleetData, error) { return testData(), nil }
	}
	return NewModel(context.Background(), testData(), reload)
}

func press(t *testing.T, m Model, keys ...string) Model {
	t.Helper()
	for _, k := range keys {
		var msg tea.KeyMsg
		switch k {
		case "tab":
			msg = tea.KeyMsg{Type: tea.KeyTab}
		case "enter":
			msg = tea.KeyMsg{Type: tea.KeyEnter}
		case "esc":
			msg = tea.KeyMsg{Type: tea.KeyEsc}
		case "up":
			msg = tea.KeyMsg{Type: tea.KeyUp}
		case "down":
			msg = tea.KeyMsg{Type: tea.KeyDown}
		default:
			msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
		}
		nm, _ := m.Update(msg)
		m = nm.(Model)
	}
	return m
}

func TestViewDefaultPeersTable(t *testing.T) {
	m := newTestModel(nil)
	v := m.View()
	for _, want := range []string{
		"db /tmp/state.db", "rev 7", "ca v2",
		"NAME", "ADDRESS", "USER", "GROUPS", "ALLOWED", "INBOUND", "REVOKED", "SERIAL", "EXPIRES",
		"alpha", "10.0.0.5", "alice", "infra", "ops", "2027-03-01",
		"beta", "gamma", "∞",
	} {
		if !strings.Contains(v, want) {
			t.Errorf("peers view missing %q:\n%s", want, v)
		}
	}
}

func TestNullCertRendersDash(t *testing.T) {
	m := newTestModel(nil)
	for _, line := range strings.Split(m.View(), "\n") {
		if strings.Contains(line, "beta") {
			if got := strings.TrimRight(line, " "); !strings.HasSuffix(got, "-") {
				t.Fatalf("beta EXPIRES cell should be %q, line: %q", "-", line)
			}
			return
		}
	}
	t.Fatal("no row for beta")
}

func TestViewSwitching(t *testing.T) {
	m := newTestModel(nil)
	if m.view != viewPeers {
		t.Fatalf("default view = %v, want peers", m.view)
	}
	m = press(t, m, "2")
	if m.view != viewGroups {
		t.Fatalf("after '2' view = %v, want groups", m.view)
	}
	v := m.View()
	for _, want := range []string{"PEERS", "infra", "── group: infra", "members (2): alpha,beta", "allowed inbound by (1): gamma"} {
		if !strings.Contains(v, want) {
			t.Errorf("groups view missing %q:\n%s", want, v)
		}
	}
	m = press(t, m, "1")
	if m.view != viewPeers {
		t.Fatalf("after '1' view = %v, want peers", m.view)
	}
	m = press(t, m, "tab")
	if m.view != viewGroups {
		t.Fatalf("after tab view = %v, want groups", m.view)
	}
	m = press(t, m, "tab")
	if m.view != viewStatus {
		t.Fatalf("after second tab view = %v, want status", m.view)
	}
	m = press(t, m, "tab")
	if m.view != viewNet {
		t.Fatalf("after third tab view = %v, want net", m.view)
	}
	m = press(t, m, "tab")
	if m.view != viewPeers {
		t.Fatalf("after fourth tab view = %v, want peers", m.view)
	}
}

func TestNavigation(t *testing.T) {
	m := newTestModel(nil)
	m = press(t, m, "j", "j")
	if m.peerIdx != 2 {
		t.Fatalf("peerIdx = %d, want 2", m.peerIdx)
	}
	m = press(t, m, "j")
	if m.peerIdx != 2 {
		t.Fatalf("peerIdx clamped = %d, want 2", m.peerIdx)
	}
	m = press(t, m, "k", "up")
	if m.peerIdx != 0 {
		t.Fatalf("peerIdx = %d, want 0", m.peerIdx)
	}
	m = press(t, m, "down")
	if m.peerIdx != 1 {
		t.Fatalf("peerIdx = %d, want 1", m.peerIdx)
	}
	m = press(t, m, "2", "j")
	if m.groupIdx != 1 {
		t.Fatalf("groupIdx = %d, want 1", m.groupIdx)
	}
}

func TestPeerDetail(t *testing.T) {
	m := press(t, newTestModel(nil), "enter")
	if !m.detail {
		t.Fatal("enter should open detail")
	}
	v := m.View()
	for _, want := range []string{
		"peer: alpha", "status", "active", "fingerprint", "SHA256:fp-alpha",
		"created", "2026-01-02 15:04", "serial", "11",
		"cert", "2027-03-01", "pull token", "present (value never shown)",
	} {
		if !strings.Contains(v, want) {
			t.Errorf("detail missing %q:\n%s", want, v)
		}
	}
	m = press(t, m, "esc")
	if m.detail {
		t.Fatal("esc should close detail")
	}

	m = press(t, m, "j", "enter")
	v = m.View()
	for _, want := range []string{"peer: beta", "REVOKED", "no certificate on record", "pull token", "none"} {
		if !strings.Contains(v, want) {
			t.Errorf("revoked detail missing %q:\n%s", want, v)
		}
	}
}

func TestDetailIgnoredOnGroupsAndEmpty(t *testing.T) {
	m := press(t, newTestModel(nil), "2", "enter")
	if m.detail {
		t.Fatal("enter on groups view must not open peer detail")
	}
	empty := NewModel(context.Background(), fleetData{}, nil)
	empty = press(t, empty, "enter")
	if empty.detail {
		t.Fatal("enter with no peers must not open detail")
	}
	if !strings.Contains(empty.View(), "no peers enrolled") {
		t.Fatal("empty view missing placeholder")
	}
}

func TestFilterPeers(t *testing.T) {
	m := press(t, newTestModel(nil), "/")
	if !m.filtering {
		t.Fatal("'/' should start filtering")
	}
	m = press(t, m, "g", "m")
	if got := m.filter.Value(); got != "gm" {
		t.Fatalf("filter value = %q, want gm", got)
	}
	if n := len(m.filteredPeers()); n != 1 {
		t.Fatalf("filtered peers = %d, want 1", n)
	}
	m = press(t, m, "enter")
	if m.filtering {
		t.Fatal("enter should apply the filter")
	}
	v := m.View()
	if !strings.Contains(v, "gamma") {
		t.Fatalf("filtered view missing gamma:\n%s", v)
	}
	if strings.Contains(v, "alpha") {
		t.Fatalf("filtered view still shows alpha:\n%s", v)
	}
	if !strings.Contains(v, `filter "gm" — 1/3 shown`) {
		t.Fatalf("filter status missing:\n%s", v)
	}
	if p, ok := m.selectedPeer(); !ok || p.Name != "gamma" {
		t.Fatalf("selected peer = %+v, want gamma", p)
	}
	m = press(t, m, "esc")
	if m.filter.Value() != "" || len(m.filteredPeers()) != 3 {
		t.Fatal("esc should clear the applied filter")
	}
}

func TestFilterEscWhileTyping(t *testing.T) {
	m := press(t, newTestModel(nil), "/", "x", "y", "esc")
	if m.filtering || m.filter.Value() != "" {
		t.Fatalf("esc while typing should cancel, filtering=%v value=%q", m.filtering, m.filter.Value())
	}
}

func TestFilterGroups(t *testing.T) {
	m := press(t, newTestModel(nil), "2", "/", "o", "p", "enter")
	gs := m.filteredGroups()
	if len(gs) != 1 || gs[0].Name != "ops" {
		t.Fatalf("filtered groups = %+v, want [ops]", gs)
	}
}

func TestFuzzyMatch(t *testing.T) {
	for _, tc := range []struct {
		needle, hay string
		want        bool
	}{
		{"", "anything", true},
		{"gm", "gamma", true},
		{"gm", "alpha", false},
		{"abc", "a-b-c", true},
		{"abc", "acb", false},
	} {
		if got := fuzzyMatch(tc.needle, tc.hay); got != tc.want {
			t.Errorf("fuzzyMatch(%q, %q) = %v, want %v", tc.needle, tc.hay, got, tc.want)
		}
	}
}

func TestReload(t *testing.T) {
	calls := 0
	next := testData()
	next.FleetRev = 8
	next.Peers = append(next.Peers, peerRow{Name: "delta", DialHost: "delta", Inbound: true})
	m := newTestModel(func(ctx context.Context) (fleetData, error) {
		calls++
		return next, nil
	})
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	m = nm.(Model)
	if cmd == nil {
		t.Fatal("'r' should return a reload cmd")
	}
	nm, _ = m.Update(cmd())
	m = nm.(Model)
	if calls != 1 {
		t.Fatalf("reload calls = %d, want 1", calls)
	}
	v := m.View()
	if !strings.Contains(v, "rev 8") || !strings.Contains(v, "delta") {
		t.Fatalf("view not refreshed after reload:\n%s", v)
	}
}

func TestReloadError(t *testing.T) {
	m := newTestModel(nil)
	nm, _ := m.Update(reloadedMsg{err: errors.New("disk gone")})
	m = nm.(Model)
	if !strings.Contains(m.View(), "error: disk gone") {
		t.Fatalf("view missing load error:\n%s", m.View())
	}
	if len(m.data.Peers) != 3 {
		t.Fatal("failed reload must keep previous data")
	}
	nm, _ = m.Update(reloadedMsg{data: testData()})
	m = nm.(Model)
	if strings.Contains(m.View(), "disk gone") {
		t.Fatal("successful reload should clear the error")
	}
}

func TestQuitKeys(t *testing.T) {
	for _, msg := range []tea.KeyMsg{
		{Type: tea.KeyRunes, Runes: []rune("q")},
		{Type: tea.KeyCtrlC},
	} {
		_, cmd := newTestModel(nil).Update(msg)
		if cmd == nil {
			t.Fatalf("%s should quit", msg)
		}
		if _, ok := cmd().(tea.QuitMsg); !ok {
			t.Fatalf("%s cmd is not Quit", msg)
		}
	}
}

func wideData() fleetData {
	d := testData()
	d.DBPath = "/very/long/path/that/easily/overflows/narrow/terminals/certhold/state.db"
	d.BaseURL = "https://manager.with.a.long.hostname.example.internal:8443"
	d.Peers[0].TargetUser = "extralongusername"
	d.Peers[0].Fingerprint = "SHA256:" + strings.Repeat("a", 43)
	d.Peers[0].Groups = []string{"infrastructure-primary", "database-replicas", "observability-stack"}
	d.Peers[0].Allowed = []string{"operations-oncall", "deployment-bots"}
	d.Peers[2].Expires = certExpiry{
		state: certAt,
		from:  time.Now().Add(-100 * 24 * time.Hour),
		until: time.Now().Add(-30 * time.Hour),
	}
	d.Groups[0].Members = []string{
		"alpha", "beta", "gamma-with-a-long-name", "delta-with-a-long-name", "epsilon-with-a-long-name",
	}
	return d
}

func TestResizeKeepsLayout(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.ANSI256)
	defer lipgloss.SetColorProfile(prev)

	sawANSI := false
	sizes := []tea.WindowSizeMsg{
		{Width: 100, Height: 30}, {Width: 80, Height: 24}, {Width: 60, Height: 16}, {Width: 60, Height: 12},
	}
	for _, size := range sizes {
		m := NewModel(context.Background(), wideData(), nil)
		nm, _ := m.Update(size)
		m = nm.(Model)
		states := map[string]Model{
			"table":     m,
			"detail":    press(t, m, "enter"),
			"groups":    press(t, m, "2"),
			"status":    press(t, m, "3"),
			"net":       press(t, m, "4"),
			"filtering": press(t, m, "/", "a"),
		}
		for name, state := range states {
			v := state.View()
			if strings.Contains(v, "\x1b[") {
				sawANSI = true
			}
			lines := strings.Split(v, "\n")
			if len(lines) != size.Height {
				t.Fatalf("%dx%d %s: got %d lines", size.Width, size.Height, name, len(lines))
			}
			for _, l := range lines {
				if lw := lipgloss.Width(l); lw > size.Width {
					t.Fatalf("%dx%d %s: line overflows (%d > %d): %q",
						size.Width, size.Height, name, lw, size.Width, l)
				}
			}
		}
	}
	if !sawANSI {
		t.Fatal("forced color profile produced no ANSI — overflow checks are vacuous")
	}
}

func TestNarrowWidthsKeepCriticalColumns(t *testing.T) {
	d := testData()
	d.Peers[0].TargetUser = "extralongusername"
	for _, size := range []tea.WindowSizeMsg{{Width: 80, Height: 24}, {Width: 60, Height: 12}} {
		m := NewModel(context.Background(), d, nil)
		nm, _ := m.Update(size)
		m = nm.(Model)
		v := m.View()
		for _, want := range []string{"REVOKED", "EXPIRES", "2027-03-01"} {
			if !strings.Contains(v, want) {
				t.Errorf("%dx%d: view missing %q:\n%s", size.Width, size.Height, want, v)
			}
		}
		var betaLine string
		for _, l := range strings.Split(v, "\n") {
			if strings.Contains(l, "beta") {
				betaLine = l
				break
			}
		}
		if !strings.Contains(betaLine, "Y") {
			t.Errorf("%dx%d: beta's REVOKED flag not visible: %q", size.Width, size.Height, betaLine)
		}
	}
}

func TestDetailPinnedAcrossReload(t *testing.T) {
	m := press(t, newTestModel(nil), "j", "enter")
	if m.detailName != "beta" {
		t.Fatalf("detailName = %q, want beta", m.detailName)
	}
	if !strings.Contains(m.View(), "peer: beta") {
		t.Fatalf("detail should show beta:\n%s", m.View())
	}

	shifted := testData()
	shifted.Peers = append([]peerRow{{Name: "aardvark", DialHost: "aardvark", Inbound: true}}, shifted.Peers...)
	nm, _ := m.Update(reloadedMsg{data: shifted})
	m = nm.(Model)
	if !strings.Contains(m.View(), "peer: beta") {
		t.Fatalf("detail must stay pinned to beta after an insertion shifts order:\n%s", m.View())
	}
	back := press(t, m, "esc")
	if back.detail {
		t.Fatal("esc should close detail")
	}
	if back.peerIdx != 2 {
		t.Fatalf("esc should re-point selection at beta, peerIdx = %d, want 2", back.peerIdx)
	}

	removed := testData()
	removed.Peers = []peerRow{removed.Peers[0], removed.Peers[2]}
	nm, _ = m.Update(reloadedMsg{data: removed})
	m = nm.(Model)
	if !strings.Contains(m.View(), "peer no longer present") {
		t.Fatalf("detail for a removed peer must show the placeholder:\n%s", m.View())
	}
	m = press(t, m, "esc")
	if m.detail {
		t.Fatal("esc must close the placeholder detail")
	}
}

func TestErrorAndFilterStatusCoexist(t *testing.T) {
	m := press(t, newTestModel(nil), "/", "a", "l", "p", "enter")
	nm, _ := m.Update(reloadedMsg{err: errors.New("disk gone")})
	m = nm.(Model)
	v := m.View()
	if !strings.Contains(v, "error: disk gone") {
		t.Fatalf("view missing load error:\n%s", v)
	}
	if !strings.Contains(v, `filter "alp" — 1/3 shown`) {
		t.Fatalf("load error must not hide the filter status:\n%s", v)
	}
}

func TestScrollCue(t *testing.T) {
	d := testData()
	for i := 0; i < 10; i++ {
		d.Peers = append(d.Peers, peerRow{Name: fmt.Sprintf("peer%02d", i), DialHost: "host"})
	}
	m := NewModel(context.Background(), d, nil)
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 60, Height: 12})
	m = nm.(Model)
	if v := m.View(); !strings.Contains(v, "1/13 ▼") {
		t.Fatalf("overflowing table missing scroll cue:\n%s", v)
	}
	for i := 0; i < 12; i++ {
		m = press(t, m, "j")
	}
	if v := m.View(); !strings.Contains(v, "▲ 13/13") {
		t.Fatalf("bottom of list missing position cue:\n%s", v)
	}
}

func TestDetailClippedShowsMore(t *testing.T) {
	m := press(t, newTestModel(nil), "enter")
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 10})
	m = nm.(Model)
	v := m.View()
	if !strings.Contains(v, "more — enlarge the terminal") {
		t.Fatalf("clipped detail missing 'more' indicator:\n%s", v)
	}
	for _, want := range []string{"status", "cert"} {
		if !strings.Contains(v, want) {
			t.Errorf("clipped detail must keep %q visible:\n%s", want, v)
		}
	}
}

func TestFooterHintsPerState(t *testing.T) {
	m := newTestModel(nil)
	if !strings.Contains(m.View(), "enter detail") {
		t.Fatal("peers hints missing 'enter detail'")
	}
	g := press(t, m, "2")
	if strings.Contains(g.View(), "enter detail") {
		t.Fatal("groups hints must not advertise enter (it is a no-op)")
	}
	if !strings.Contains(g.View(), "j/k move") {
		t.Fatal("groups hints missing movement keys")
	}
	s := press(t, m, "3")
	if !strings.Contains(s.View(), "r refresh") {
		t.Fatal("status hints missing 'r refresh'")
	}
	if strings.Contains(s.View(), "/ filter") {
		t.Fatal("status hints must not advertise filtering (it is a no-op)")
	}
	d := press(t, m, "enter")
	dv := d.View()
	for _, want := range []string{"esc back", "tab/1/2/3/4 views", "/ filter"} {
		if !strings.Contains(dv, want) {
			t.Errorf("detail hints missing %q:\n%s", want, dv)
		}
	}
	f := press(t, m, "/")
	if !strings.Contains(f.View(), "enter apply") {
		t.Fatal("filtering hints missing 'enter apply'")
	}
}

func TestFilterPerView(t *testing.T) {
	m := press(t, newTestModel(nil), "/", "a", "l", "p", "enter")
	if n := len(m.filteredPeers()); n != 1 {
		t.Fatalf("filtered peers = %d, want 1", n)
	}
	m = press(t, m, "2")
	if n := len(m.filteredGroups()); n != 2 {
		t.Fatalf("groups view inherited the peers filter: %d groups shown, want 2", n)
	}
	if strings.Contains(m.View(), `filter "alp"`) {
		t.Fatal("groups footer must not show the peers filter")
	}
	m = press(t, m, "/", "o", "p", "enter")
	gs := m.filteredGroups()
	if len(gs) != 1 || gs[0].Name != "ops" {
		t.Fatalf("filtered groups = %+v, want [ops]", gs)
	}
	m = press(t, m, "1")
	if n := len(m.filteredPeers()); n != 1 {
		t.Fatalf("peers filter must persist independently, got %d peers", n)
	}
}

func TestTextualMarkersSurviveNoColor(t *testing.T) {
	m := newTestModel(nil)
	v := m.View()
	if !strings.Contains(v, "[1 peers (3)]") {
		t.Fatalf("active tab missing textual marker:\n%s", v)
	}
	var selLine string
	for _, l := range strings.Split(v, "\n") {
		if strings.HasPrefix(l, selMarker) {
			selLine = l
			break
		}
	}
	if !strings.Contains(selLine, "alpha") {
		t.Fatalf("selected row missing %q marker:\n%s", selMarker, v)
	}
	if gv := press(t, m, "2").View(); !strings.Contains(gv, "[2 groups (2)]") {
		t.Fatalf("groups tab missing textual marker:\n%s", gv)
	}
	if dv := press(t, m, "enter").View(); !strings.Contains(dv, "[peer detail]") {
		t.Fatalf("detail badge missing textual marker:\n%s", dv)
	}
}

func TestLiveMatchCountWhileFiltering(t *testing.T) {
	m := press(t, newTestModel(nil), "/", "g", "m")
	if v := m.View(); !strings.Contains(v, "1/3 match") {
		t.Fatalf("typing a filter must show the live match count:\n%s", v)
	}
	m = press(t, m, "x")
	if v := m.View(); !strings.Contains(v, "0/3 match") {
		t.Fatalf("live match count not updated:\n%s", v)
	}
}
