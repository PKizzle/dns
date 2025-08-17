package jump

import (
	"fmt"
	"os"
	"testing"

	"codeberg.org/miekg/dns/internal/bin"
)

func TestName(t *testing.T) {
	testcases := []struct {
		buf   []byte
		start int
		off   int
		fn    func([]byte, int) int
	}{
		// miek.nl (4 miek 2 nl 0)
		{[]byte{4, 109, 105, 101, 107, 2, 110, 108, 0}, 0, 9, Name},
		// beginning of a message, ID (98, 24),... then miek.nl as question = 0 15 (mx as type) and 0 01 as
		// class. But then 192 12 which is a pointer to miek.nl, so lets decode that.
		{[]byte{98, 24, 129, 128, 0, 1, 0, 5, 0, 0, 0, 1, 4, 109, 105, 101, 107, 2, 110, 108, 0, 0, 15, 0, 1, 192, 12, 0}, 25, 27, Name},
		// Almost entire message... we are starting '192,12,0,15'; name pointer and then mx type.
		// 21,61 -> ttl, then 0,27 -> rdlength, 0, 5 -> mx prio, then 4,97...,5,95: alt1.aspmx.l.google.com.
		{[]byte{21, 33, 129, 128, 0, 1, 0, 5, 0, 0, 0, 1, 4, 109, 105, 101, 107, 2, 110, 108, 0, 0, 15, 0, 1, 192, 12, 0, 15, 0, 1, 0, 0, 21, 61, 0, 27, 0, 5, 4, 97, 108, 116, 49, 5, 97, 115, 112, 109, 120, 1, 108, 6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0}, 26, 64, RR},
		// miek.nl (4 miek 2 nl), no null byte, should terminate.
		{[]byte{4, 109, 105, 101, 107, 2, 110, 108}, 2, 0, Name},
	}
	for i, tc := range testcases {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			off := Name(tc.buf, tc.start)
			if off != tc.off {
				t.Errorf("expected offset %d, got %d", tc.off, off)
			}
		})
	}
}

func TestTo(t *testing.T) {
	testcases := []struct {
		binary string
		rrs    int
		off    int
	}{
		//		{"dig-mx-miek.nl", 0, 25},
		//		{"dig-mx-miek.nl", 1, 62},
		//		{"dig-mx-miek.nl", 2, 98},
		//		{"dig-mx-miek.nl", 3, 114},
		//		{"dig-mx-miek.nl", 4, 135},
		{"dig-mx-miek.nl", 5, 158}, // OPT RR
		{"dig-mx-miek.nl", 6, 0},   // overshoot
	}
	for i, tc := range testcases {
		t.Run(fmt.Sprintf("test %d: %s", i, tc.binary), func(t *testing.T) {
			buf, _ := os.ReadFile("../../testdata/" + tc.binary)
			off := To(tc.rrs, buf)
			if off != tc.off {
				t.Errorf("expected to land on %d, got %d", tc.off, off)
				t.Logf("%v\n", buf[off:])
			}
			t.Log(bin.Dump(buf))
			t.Log(bin.Dump(buf[off:], off))
		})
	}
}
