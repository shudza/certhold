package tui

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var okStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Bold(true)

const expiringSoonWindow = 30 * 24 * time.Hour

type healthInfo struct {
	FleetRev  int64 `json:"fleet_rev"`
	CAVersion int   `json:"ca_version"`
}

type healthMsg struct {
	seq  int
	info healthInfo
	err  error
}

// defaultHealthClient skips TLS verification: serve presents a self-signed
// certificate and /healthz carries only public counters.
func defaultHealthClient() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func fetchHealth(ctx context.Context, client *http.Client, baseURL string) (healthInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/healthz", nil)
	if err != nil {
		return healthInfo{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return healthInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return healthInfo{}, fmt.Errorf("healthz: HTTP %d", resp.StatusCode)
	}
	var info healthInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&info); err != nil {
		return healthInfo{}, fmt.Errorf("healthz: %w", err)
	}
	return info, nil
}

// healthCmd numbers each fetch and clears the shown result so the view reads
// "checking…" while a refetch is in flight; a result from a superseded fetch
// is dropped on arrival instead of overwriting a newer one.
func (m *Model) healthCmd() tea.Cmd {
	if m.data.BaseURL == "" {
		return nil
	}
	m.healthSeq++
	m.serve = nil
	seq, ctx, client, baseURL := m.healthSeq, m.ctx, m.health, m.data.BaseURL
	return func() tea.Msg {
		info, err := fetchHealth(ctx, client, baseURL)
		return healthMsg{seq: seq, info: info, err: err}
	}
}

func (m Model) statusLines(w, bodyH int) []string {
	var inbound, clients, revoked, expired, expiring int
	now := time.Now()
	for _, p := range m.data.Peers {
		if p.Inbound {
			inbound++
		} else {
			clients++
		}
		if p.Revoked {
			revoked++
		}
		switch {
		case p.Expires.expired():
			expired++
		case p.Expires.expiringWithin(expiringSoonWindow, now):
			expiring++
		}
	}
	ca := "-"
	if m.data.CAVersionKnown {
		ca = fmt.Sprintf("v%d", m.data.CAVersion)
	}
	field := func(label, value string) string {
		return truncLine(labelStyle.Render(fmt.Sprintf("%-13s", label))+value, w)
	}
	expiredSeg := fmt.Sprintf("%d expired", expired)
	if expired > 0 {
		expiredSeg = expiredStyle.Render(expiredSeg)
	}
	expiringSeg := fmt.Sprintf("%d expiring ≤30d", expiring)
	if expiring > 0 {
		expiringSeg = warnStyle.Render(expiringSeg)
	}
	// SERVE leads and sections pack without separators so liveness (incl.
	// STALE/down) survives short terminals, which clip from the bottom.
	lines := []string{truncLine(colHeadStyle.Render("SERVE"), w)}
	lines = append(lines, m.serveLines(w)...)
	lines = append(lines,
		truncLine(colHeadStyle.Render("FLEET"), w),
		field("peers", fmt.Sprintf("%d total · %d inbound · %d client", len(m.data.Peers), inbound, clients)),
		field("revoked", fmt.Sprintf("%d", revoked)),
		field("certs", expiredSeg+" · "+expiringSeg),
		truncLine(colHeadStyle.Render("MANAGER"), w),
		field("fleet rev", fmt.Sprintf("%d", m.data.FleetRev)),
		field("ca", ca),
	)
	if len(lines) > bodyH && bodyH >= 2 {
		hidden := len(lines) - (bodyH - 1)
		lines = append(lines[:bodyH-1:bodyH-1],
			dimStyle.Render(fmt.Sprintf("… %d more — enlarge the terminal", hidden)))
	}
	return lines
}

func (m Model) serveLines(w int) []string {
	switch {
	case m.data.BaseURL == "":
		return []string{truncLine(dimStyle.Render("serve: unknown (no base_url)"), w)}
	case m.serve == nil:
		return []string{truncLine(dimStyle.Render("serve: checking "+m.data.BaseURL+" …"), w)}
	case m.serve.err != nil:
		return []string{truncLine(errStyle.Render("serve: down")+
			dimStyle.Render(" — "+m.serve.err.Error()), w)}
	}
	info := m.serve.info
	lines := []string{truncLine(okStyle.Render("serve: up")+
		metaStyle.Render(fmt.Sprintf(" — rev %d · ca v%d · %s", info.FleetRev, info.CAVersion, m.data.BaseURL)), w)}
	if info.FleetRev != m.data.FleetRev {
		lines = append(lines, truncLine(errStyle.Render(
			fmt.Sprintf("STALE: serve rev %d ≠ db rev %d (r reloads)", info.FleetRev, m.data.FleetRev)), w))
	}
	return lines
}
