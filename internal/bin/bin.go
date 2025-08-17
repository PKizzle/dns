// Package bin pretty prints a byte slice.
package bin

import (
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"
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
// Usally called as: t.Log(bin.Dump(buf))
func Dump(p []byte, off ...int) string {
	if len(p) == 0 {
		return ""
	}

	const space = "   "
	left := func(s string) string {
		switch l := len(s); l {
		case 0, 1, 2, 3:
			return space[:3-l] + s
		default:
			return s[:3]
		}
	}
	right := func(s string) string {
		if len(s) < 3 {
			return space
		}
		s = s[3:]
		switch l := len(s); l {
		case 0, 1, 2, 3:
			return s[:l] + space[:3-l]
		default:
			return s[:3]
		}
	}
	// create a lookup table for bytes we have detected to be some of importants like
	// type (after a compression pointer) and the class (after the type) - if detected we print the mnemonic
	// instead of the binary, split between the 3 and 3 chars we have, MX will be "MX_ ___" and RRSIG will be
	// "RRS _IG" for instance.
	strlist := map[int]string{}

	state := 0 // 0, nothing
	// 1, expect type
	// 2, expect class
	for i := 0; i < len(p)-1; i++ {
		c := p[i]
		c1 := p[i+1]
		if c == 192 { // 0xC with a small enough pointer (check smallness? 12)
			state = 1
			i++ // skip pointer
			continue
		}
		switch state {
		case 1:
			rrtype, ok := dns.TypeToString[uint16(c+c1)]
			if !ok {
				continue
			}
			strlist[i], strlist[i+1] = left(rrtype), right(rrtype)
			i++
			if uint16(c+c1) == dns.TypeOPT {
				state = 0
				continue
			}
			state = 2

		case 2:
			class, ok := dns.ClassToString[uint16(c+c1)]
			if !ok {
				continue
			}
			strlist[i], strlist[i+1] = left(class), right(class)
			i++

			state = 0
		}
	}

	const N = 16
	dump := strings.Builder{}
	dump.WriteByte('\n') // usually called from test
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
			if str, ok := strlist[j+a]; ok {
				sb.WriteByte(' ')
				sb.WriteString(str)
				continue
			}

			sb.WriteByte(' ')
			sb.WriteString(fmt.Sprintf("%03d", line[j]))
		}

		dump.WriteString(fmt.Sprintf("%5d\t|%s\n", row*N+plus, sb.String()))
		row++
	}
	return dump.String()
}
