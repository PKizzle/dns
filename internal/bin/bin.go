// Package bin pretty prints a byte slice.
package bin

import (
	"fmt"
	"strings"
)

// Dump dumps the slice p in a way to help debugging DNS binary code.
// Got used to reading decimal [192 12] is a pointer etc., so that's being used here.
// If the optional off is given this is added to the counter.
//
// Output looks like:
//
//	        0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
//	0   | 098 024 129 128 000 001 000 005 000 000 000 001 004 109 105 101
//	16  | 107 002 110 108 000 000 015 000 001 192 012 000 015 000 001 000
//	32  | 000 084 096 000 025 000 010 006 097 115 112 109 120 050 010 103
//
// Usually called as: t.Logf("\n%s\n", bin.Dump(buf))
func Dump(p []byte, off ...int) string {
	if len(p) == 0 {
		return ""
	}

	const N = 16
	dump := strings.Builder{}
	dump.WriteString("     \t")
	for i := range N {
		dump.WriteString(fmt.Sprintf("% 4d", i))
	}
	dump.WriteByte('\n')
	dump.WriteByte('\n')

	row := 0
	plus := 0
	if len(off) > 0 {
		plus = (off[0] / N) * N
	}

	sb := strings.Builder{}
	for i := 0; i*N < len(p); i++ {
		a, b := i*N, (i+1)*N
		if b > len(p) {
			b = len(p)
		}

		line := p[a:b]
		sb.Reset()
		for j := range line {
			sb.WriteByte(' ')
			sb.WriteString(fmt.Sprintf("%03d", line[j]))
		}

		dump.WriteString(fmt.Sprintf("%5d\t|%s\n", row*N+plus, sb.String()))
		row++
	}
	return dump.String()
}
