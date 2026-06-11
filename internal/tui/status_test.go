package tui

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

type fakeRT func(*http.Request) (*http.Response, error)

func (f fakeRT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fakeHealthClient(fn fakeRT) *http.Client {
	return &http.Client{Transport: fn}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// pressStatusAndFetch enters the status view and pumps the resulting health
// command back through Update, the message-driven equivalent of the program loop.
func pressStatusAndFetch(t *testing.T, m Model) Model {
	t.Helper()
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("3")})
	m = nm.(Model)
	if cmd == nil {
		t.Fatal("entering status with a base_url must return a health cmd")
	}
	nm, _ = m.Update(cmd())
	return nm.(Model)
}

func TestStatusServeUp(t *testing.T) {
	m := newTestModel(nil)
	m.data.BaseURL = "https://mgr.example:8443"
	var gotURL string
	m.health = fakeHealthClient(func(r *http.Request) (*http.Response, error) {
		gotURL = r.URL.String()
		return jsonResponse(http.StatusOK, `{"fleet_rev":7,"ca_version":2}`), nil
	})
	m = pressStatusAndFetch(t, m)
	if gotURL != "https://mgr.example:8443/healthz" {
		t.Fatalf("fetched %q, want base_url + /healthz", gotURL)
	}
	v := m.View()
	if !strings.Contains(v, "serve: up") {
		t.Fatalf("status view missing 'serve: up':\n%s", v)
	}
	if strings.Contains(v, "STALE") {
		t.Fatalf("matching revs must not be flagged stale:\n%s", v)
	}
}

func TestStatusServeDownTimeout(t *testing.T) {
	m := newTestModel(nil)
	m.data.BaseURL = "https://mgr.example:8443"
	m.health = fakeHealthClient(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("dial tcp 203.0.113.7:8443: i/o timeout")
	})
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 24})
	m = pressStatusAndFetch(t, nm.(Model))
	v := m.View()
	if !strings.Contains(v, "serve: down") {
		t.Fatalf("status view missing 'serve: down':\n%s", v)
	}
	if !strings.Contains(v, "i/o timeout") {
		t.Fatalf("down line missing the error:\n%s", v)
	}
}

func TestStatusServeNon200(t *testing.T) {
	m := newTestModel(nil)
	m.data.BaseURL = "https://mgr.example:8443"
	m.health = fakeHealthClient(func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusInternalServerError, `{"error":"read fleet rev failed"}`), nil
	})
	m = pressStatusAndFetch(t, m)
	v := m.View()
	if !strings.Contains(v, "serve: down") || !strings.Contains(v, "HTTP 500") {
		t.Fatalf("non-200 must render as down with the code:\n%s", v)
	}
}

func TestStatusRevMismatchFlagged(t *testing.T) {
	m := newTestModel(nil)
	m.data.BaseURL = "https://mgr.example:8443"
	m.health = fakeHealthClient(func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"fleet_rev":9,"ca_version":2}`), nil
	})
	m = pressStatusAndFetch(t, m)
	v := m.View()
	if !strings.Contains(v, "serve: up") {
		t.Fatalf("mismatch is still up:\n%s", v)
	}
	if !strings.Contains(v, "STALE: serve rev 9 ≠ db rev 7") {
		t.Fatalf("rev mismatch not flagged:\n%s", v)
	}
}

func TestStatusNoBaseURL(t *testing.T) {
	m := newTestModel(nil)
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("3")})
	m = nm.(Model)
	if cmd != nil {
		t.Fatal("no base_url must not attempt a health fetch")
	}
	if !strings.Contains(m.View(), "serve: unknown (no base_url)") {
		t.Fatalf("status view missing base_url placeholder:\n%s", m.View())
	}
}

func TestStatusCheckingBeforeResult(t *testing.T) {
	m := newTestModel(nil)
	m.data.BaseURL = "https://mgr.example:8443"
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("3")})
	m = nm.(Model)
	if cmd == nil {
		t.Fatal("entering status must return a health cmd")
	}
	if !strings.Contains(m.View(), "serve: checking https://mgr.example:8443") {
		t.Fatalf("pre-result view missing checking line:\n%s", m.View())
	}
}

func TestStatusCounts(t *testing.T) {
	d := testData()
	d.Peers = append(d.Peers,
		peerRow{Name: "old", DialHost: "old", Inbound: true,
			Expires: certExpiry{state: certAt, until: time.Now().Add(-time.Hour)}},
		peerRow{Name: "soon", DialHost: "soon", Inbound: true,
			Expires: certExpiry{state: certAt, until: time.Now().Add(10 * 24 * time.Hour)}},
	)
	m := NewModel(context.Background(), d, nil)
	v := press(t, m, "3").View()
	for _, want := range []string{
		"FLEET", "MANAGER", "SERVE",
		"5 total · 4 inbound · 1 client",
		"revoked", "1 expired · 1 expiring ≤30d",
		"fleet rev", "ca", "v2",
	} {
		if !strings.Contains(v, want) {
			t.Errorf("status view missing %q:\n%s", want, v)
		}
	}
}

func TestExpiringWithinBoundaries(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	at := func(d time.Duration) certExpiry {
		return certExpiry{state: certAt, until: now.Add(d)}
	}
	for _, tc := range []struct {
		name string
		e    certExpiry
		want bool
	}{
		{"29d", at(29 * day), true},
		{"30d exact", at(30 * day), true},
		{"31d", at(31 * day), false},
		{"already expired", at(-time.Hour), false},
		{"no cert", certExpiry{state: certNone}, false},
		{"forever", certExpiry{state: certForever}, false},
	} {
		if got := tc.e.expiringWithin(30*day, now); got != tc.want {
			t.Errorf("%s: expiringWithin = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestStatusTabAndFooter(t *testing.T) {
	m := newTestModel(nil)
	m = press(t, m, "3")
	if m.view != viewStatus {
		t.Fatalf("after '3' view = %v, want status", m.view)
	}
	v := m.View()
	if !strings.Contains(v, "[3 status]") {
		t.Fatalf("status tab missing textual marker:\n%s", v)
	}
	if !strings.Contains(v, "tab/1/2/3 views · r refresh · q quit") {
		t.Fatalf("status footer hints wrong:\n%s", v)
	}
	m = press(t, m, "1", "tab", "tab")
	if m.view != viewStatus {
		t.Fatalf("tab,tab from peers = %v, want status", m.view)
	}
	m = press(t, m, "tab")
	if m.view != viewPeers {
		t.Fatalf("tab from status = %v, want peers", m.view)
	}
}

func TestStatusKeysAreNoops(t *testing.T) {
	m := press(t, newTestModel(nil), "3")
	m = press(t, m, "j", "enter", "/")
	if m.filtering {
		t.Fatal("'/' must be a no-op on the status view")
	}
	if m.detail {
		t.Fatal("enter must not open a detail pane from status")
	}
	if m.view != viewStatus {
		t.Fatalf("view = %v, want status", m.view)
	}
}

func TestStatusRefreshKey(t *testing.T) {
	reloads := 0
	m := newTestModel(func(ctx context.Context) (fleetData, error) {
		reloads++
		return testData(), nil
	})
	m.data.BaseURL = "https://mgr.example:8443"
	fetches := 0
	m.health = fakeHealthClient(func(r *http.Request) (*http.Response, error) {
		fetches++
		return jsonResponse(http.StatusOK, `{"fleet_rev":7,"ca_version":2}`), nil
	})
	m = pressStatusAndFetch(t, m)
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	m = nm.(Model)
	if cmd == nil {
		t.Fatal("'r' on status must return a cmd")
	}
	batch, ok := cmd().(tea.BatchMsg)
	if !ok {
		t.Fatalf("'r' on status must batch reload and health check, got %T", cmd())
	}
	for _, c := range batch {
		nm, _ = m.Update(c())
		m = nm.(Model)
	}
	if reloads != 1 || fetches != 2 {
		t.Fatalf("reloads = %d fetches = %d, want 1 and 2", reloads, fetches)
	}
}

func TestStatusLayoutClamped(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.ANSI256)
	defer lipgloss.SetColorProfile(prev)

	responses := map[string]func(*http.Request) (*http.Response, error){
		"up": func(r *http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{"fleet_rev":7,"ca_version":2}`), nil
		},
		"stale": func(r *http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{"fleet_rev":99,"ca_version":2}`), nil
		},
		"down": func(r *http.Request) (*http.Response, error) {
			return nil, errors.New("dial tcp 203.0.113.7:8443: connect: connection timed out after a very long unreachable route")
		},
	}
	sawANSI := false
	for name, fn := range responses {
		for _, size := range []tea.WindowSizeMsg{{Width: 100, Height: 30}, {Width: 60, Height: 12}, {Width: 40, Height: 10}} {
			m := NewModel(context.Background(), wideData(), nil)
			m.data.BaseURL = "https://manager.with.a.long.hostname.example.internal:8443"
			m.health = fakeHealthClient(fn)
			nm, _ := m.Update(size)
			m = pressStatusAndFetch(t, nm.(Model))
			v := m.View()
			if strings.Contains(v, "\x1b[") {
				sawANSI = true
			}
			lines := strings.Split(v, "\n")
			if len(lines) != size.Height {
				t.Fatalf("%s %dx%d: got %d lines", name, size.Width, size.Height, len(lines))
			}
			for _, l := range lines {
				if lw := lipgloss.Width(l); lw > size.Width {
					t.Fatalf("%s %dx%d: line overflows (%d > %d): %q", name, size.Width, size.Height, lw, size.Width, l)
				}
			}
		}
	}
	if !sawANSI {
		t.Fatal("forced color profile produced no ANSI — overflow checks are vacuous")
	}
}
