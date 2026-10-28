// Package qr renders a string as a QR code made of terminal text, packing two
// module rows into each line with Unicode half-blocks.
package qr

import (
	"strings"

	rscqr "rsc.io/qr"
)

// QuietZone is the light border, in modules, drawn on the left, right and top
// of the code. The bottom border is one module taller so the total row count
// is even and every text line holds exactly two module rows.
const QuietZone = 2

// Lines renders text as a QR code. Glyph cells are light modules and blank
// cells are dark, so the result reads correctly when drawn light-on-dark; Color
// pins those colors for terminals with a light theme. Every line has the same
// cell width.
func Lines(text string) ([]string, error) {
	code, err := rscqr.Encode(text, rscqr.L)
	if err != nil {
		return nil, err
	}
	side := code.Size + 2*QuietZone
	rows := code.Size + 2*QuietZone + 1
	light := func(x, y int) bool {
		return !code.Black(x-QuietZone, y-QuietZone)
	}
	out := make([]string, 0, rows/2)
	var b strings.Builder
	for y := 0; y < rows; y += 2 {
		b.Reset()
		for x := 0; x < side; x++ {
			switch top, bottom := light(x, y), light(x, y+1); {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteByte(' ')
			}
		}
		out = append(out, b.String())
	}
	return out, nil
}

// Color wraps each line in ANSI SGR codes for bright-white glyphs on a black
// background, so the code scans the same on light and dark terminal themes.
func Color(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = "\x1b[97;40m" + l + "\x1b[0m"
	}
	return out
}
