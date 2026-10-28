package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/shudza/certhold/internal/ops"
	"github.com/shudza/certhold/internal/qr"
)

const testOneLiner = "curl -kfsSL https://certhold.home.lan/enroll/zh7_ByXd9epfrwqyaA0w54t--_lUDRxUmAP8_VZb_ZE.sh | bash"

func resultModalFor(t *testing.T, client, reenroll bool) (enrollResultModal, []string) {
	t.Helper()
	code, err := qr.Lines(testOneLiner)
	if err != nil {
		t.Fatalf("qr.Lines: %v", err)
	}
	m := newEnrollResultModal(ops.EnrollResult{PeerName: "edge1", OneLiner: testOneLiner, Reenroll: reenroll}, client)
	return m, code
}

func framed(m enrollResultModal, w, h int) string {
	return strings.Join(modalFrame(nil, m, w, h), "\n")
}

func withProfile(t *testing.T, p termenv.Profile) {
	t.Helper()
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(p)
	t.Cleanup(func() { lipgloss.SetColorProfile(prev) })
}

func TestEnrollResultBigFrameShowsWholeQR(t *testing.T) {
	withProfile(t, termenv.ANSI256)

	for _, tc := range []struct {
		name             string
		w, h             int
		client, reenroll bool
	}{
		{"plain 100x31", 100, 31, false, false},
		{"client 120x50", 120, 50, true, false},
		{"reenroll 80x60", 80, 60, false, true},
	} {
		m, code := resultModalFor(t, tc.client, tc.reenroll)
		v := framed(m, tc.w, tc.h)
		for i, l := range code {
			if !strings.Contains(v, qrStyle.Render(l)) {
				t.Fatalf("%s: QR line %d missing or clipped:\n%s", tc.name, i, v)
			}
		}
		if strings.Contains(v, qrHint) {
			t.Fatalf("%s: hint shown although the QR fits:\n%s", tc.name, v)
		}
		if !strings.Contains(v, "esc dismiss") {
			t.Fatalf("%s: dismiss hint pushed out of the frame:\n%s", tc.name, v)
		}
		body := m.view(tc.w, modalBodyHeight(tc.h))
		last := wrapPlain(testOneLiner, tc.w-4)
		idx := -1
		for i, l := range body {
			if l == last[len(last)-1] {
				idx = i
			}
		}
		if idx < 0 || body[idx+1] != "" || body[idx+2] != qrStyle.Render(code[0]) {
			t.Fatalf("%s: QR does not start one blank line under the one-liner:\n%s", tc.name, strings.Join(body, "\n"))
		}
	}
}

func TestEnrollResultSmallFrameShowsHintNotQR(t *testing.T) {
	withProfile(t, termenv.ANSI256)

	_, code := resultModalFor(t, false, false)
	for _, tc := range []struct {
		name             string
		w, h             int
		client, reenroll bool
	}{
		{"short 100x30", 100, 30, false, false},
		{"80x24", 80, 24, false, false},
		{"narrow 40x60", 40, 60, false, false},
		{"client fills 100x32", 100, 32, true, false},
	} {
		m, _ := resultModalFor(t, tc.client, tc.reenroll)
		v := framed(m, tc.w, tc.h)
		for _, r := range "█▀▄" {
			if strings.ContainsRune(v, r) {
				t.Fatalf("%s: QR glyph %q rendered in a frame too small for the code:\n%s", tc.name, r, v)
			}
		}
		if !strings.Contains(v, "enlarge the terminal") {
			t.Fatalf("%s: missing hint line:\n%s", tc.name, v)
		}
		if !strings.Contains(v, "esc dismiss") {
			t.Fatalf("%s: dismiss hint pushed out of the frame:\n%s", tc.name, v)
		}
	}
	if lipgloss.Width(code[0]) <= 40-4 {
		t.Fatalf("narrow case is vacuous: QR is %d cells wide", lipgloss.Width(code[0]))
	}
}

func TestEnrollResultQRStyledUnderColor(t *testing.T) {
	withProfile(t, termenv.ANSI256)

	m, code := resultModalFor(t, false, false)
	v := framed(m, 120, 50)
	if !strings.Contains(v, qrStyle.Render(code[0])) {
		t.Fatalf("QR lines are not drawn with the fixed light-on-dark style:\n%q", v)
	}
	for _, l := range strings.Split(v, "\n") {
		if lw := lipgloss.Width(l); lw > 120 {
			t.Fatalf("line overflows (%d): %q", lw, l)
		}
	}
}

func TestEnrollResultNoColorShowsHintNotQR(t *testing.T) {
	withProfile(t, termenv.Ascii)

	m, _ := resultModalFor(t, false, false)
	v := framed(m, 200, 80)
	for _, r := range "█▀▄" {
		if strings.ContainsRune(v, r) {
			t.Fatalf("QR glyph %q rendered without colours:\n%s", r, v)
		}
	}
	if !strings.Contains(v, qrNoColorHint) {
		t.Fatalf("missing no-colour hint:\n%s", v)
	}
	if strings.Contains(v, qrHint) {
		t.Fatalf("enlarge hint shown although size is not the problem:\n%s", v)
	}
	body := m.view(200, modalBodyHeight(80))
	last := wrapPlain(testOneLiner, 200-4)
	for i, l := range body {
		if l == last[len(last)-1] {
			if i+2 >= len(body) || body[i+1] != "" || body[i+2] != qrNoColorHint {
				t.Fatalf("hint must follow the one-liner after a blank line:\n%s", strings.Join(body, "\n"))
			}
			return
		}
	}
	t.Fatalf("one-liner not found in body:\n%s", strings.Join(body, "\n"))
}
