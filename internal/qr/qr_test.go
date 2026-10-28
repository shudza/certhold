package qr

import (
	"strings"
	"testing"
	"unicode/utf8"

	rscqr "rsc.io/qr"
)

func decodeModules(t *testing.T, lines []string) [][]bool {
	t.Helper()
	var grid [][]bool
	for i, l := range lines {
		top := make([]bool, 0, utf8.RuneCountInString(l))
		bottom := make([]bool, 0, cap(top))
		for _, r := range l {
			switch r {
			case '█':
				top, bottom = append(top, true), append(bottom, true)
			case '▀':
				top, bottom = append(top, true), append(bottom, false)
			case '▄':
				top, bottom = append(top, false), append(bottom, true)
			case ' ':
				top, bottom = append(top, false), append(bottom, false)
			default:
				t.Fatalf("line %d: unexpected rune %q", i, r)
			}
		}
		grid = append(grid, top, bottom)
	}
	return grid
}

func TestLinesRoundTripToModuleMatrix(t *testing.T) {
	inputs := []string{
		"hello",
		"curl -kfsSL https://192.168.1.10:8443/enroll/zh7_ByXd9epfrwqyaA0w54t--_lUDRxUmAP8_VZb_ZE.sh | bash",
		"curl -kfsSL https://certhold.home.lan/enroll/zh7_ByXd9epfrwqyaA0w54t--_lUDRxUmAP8_VZb_ZE.sh | bash",
	}
	for _, in := range inputs {
		lines, err := Lines(in)
		if err != nil {
			t.Fatalf("Lines(%q): %v", in, err)
		}
		code, err := rscqr.Encode(in, rscqr.L)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		side := code.Size + 2*QuietZone
		grid := decodeModules(t, lines)
		if len(grid) != side+1 {
			t.Fatalf("%q: decoded %d module rows, want %d", in, len(grid), side+1)
		}
		for y, row := range grid {
			if len(row) != side {
				t.Fatalf("%q: row %d has %d modules, want %d", in, y, len(row), side)
			}
			for x, light := range row {
				cx, cy := x-QuietZone, y-QuietZone
				inCode := cx >= 0 && cx < code.Size && cy >= 0 && cy < code.Size
				if !inCode {
					if !light {
						t.Fatalf("%q: quiet-zone module (%d,%d) is dark", in, x, y)
					}
					continue
				}
				if light == code.Black(cx, cy) {
					t.Fatalf("%q: module (%d,%d) light=%v, encoder black=%v", in, cx, cy, light, code.Black(cx, cy))
				}
			}
		}
	}
}

func TestLinesFinderPatternAtOrigin(t *testing.T) {
	lines, err := Lines("certhold")
	if err != nil {
		t.Fatal(err)
	}
	grid := decodeModules(t, lines)
	q := QuietZone
	for i := 0; i < 7; i++ {
		for _, p := range [][2]int{{i, 0}, {i, 6}, {0, i}, {6, i}} {
			if grid[q+p[1]][q+p[0]] {
				t.Fatalf("finder ring module (%d,%d) is light, want dark", p[0], p[1])
			}
		}
	}
	if !grid[q+1][q+1] || grid[q+3][q+3] {
		t.Fatal("finder pattern inner ring/center has the wrong shade")
	}
}

func TestLinesTooLong(t *testing.T) {
	if _, err := Lines(strings.Repeat("x", 4000)); err == nil {
		t.Fatal("expected an error for text beyond QR capacity")
	}
}

func TestColorWrapsEveryLine(t *testing.T) {
	got := Color([]string{"█▀", "▄ "})
	want := []string{"\x1b[97;40m█▀\x1b[0m", "\x1b[97;40m▄ \x1b[0m"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}
