package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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
	if m.view != viewPeers {
		t.Fatalf("after second tab view = %v, want peers", m.view)
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

func TestResizeKeepsLayout(t *testing.T) {
	for _, size := range []tea.WindowSizeMsg{{Width: 100, Height: 30}, {Width: 60, Height: 12}} {
		m := newTestModel(nil)
		nm, _ := m.Update(size)
		m = nm.(Model)
		for _, state := range []Model{m, press(t, m, "enter"), press(t, m, "2")} {
			lines := strings.Split(state.View(), "\n")
			if len(lines) != size.Height {
				t.Fatalf("%dx%d: got %d lines", size.Width, size.Height, len(lines))
			}
			for _, l := range lines {
				if lipgloss.Width(l) > size.Width {
					t.Fatalf("%dx%d: line overflows: %q", size.Width, size.Height, l)
				}
			}
		}
	}
}
