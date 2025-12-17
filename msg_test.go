package dns_test

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/internal/bin"
	"codeberg.org/miekg/dns/internal/unpack"
	"golang.org/x/crypto/cryptobyte"
)

// TestMakeMsg_Question tests the creation of a small Msg with a question section only, and no EDNS0. This
// checks if we create the correct wire-format.
func ExampleMsg_Question() {
	m := &dns.Msg{MsgHeader: dns.MsgHeader{ID: 3, RecursionDesired: true}}
	mx := &dns.MX{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET}}
	m.Question = []dns.RR{mx}

	m.Pack()
	fmt.Printf("%v\n", m.Data)
	// Output: [0 3 1 0 0 1 0 0 0 0 0 0 4 109 105 101 107 2 110 108 0 0 15 0 1]
}

func ExampleMsg_Pseudo_nsid() {
	m := &dns.Msg{MsgHeader: dns.MsgHeader{ID: 3, RecursionDesired: true}}
	m.Question = []dns.RR{&dns.MX{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET}}}
	m.Pseudo = []dns.RR{&dns.NSID{}}

	m.Pack()
	// 41 is OPT after the zeros, 04 -> rdlength, 03 -> code of NSID, 00 -> "rdlength" of NSID
	fmt.Printf("%v\n", m.Data)
	// Output: [0 3 1 0 0 1 0 0 0 0 0 1 4 109 105 101 107 2 110 108 0 0 15 0 1 0 0 41 0 0 0 0 0 0 0 4 0 3 0 0]
}

func TestMsgBinary(t *testing.T) {
	tcs := []struct {
		name string
		buf  []byte
		fn   func(*dns.Msg) error
	}{
		{
			"edns0-subnet",
			[]byte{149, 112, 0, 16, 0, 1, 0, 0, 0, 0, 0, 1, 1, 97, 4, 109, 105, 69, 75, 2, 78, 76, 0, 0, 1, 0, 1, 0, 0, 41, 5, 120, 0, 0, 128, 0, 0, 11, 0, 8, 0, 7, 0, 1, 24, 0, 14, 128, 63},
			func(m *dns.Msg) error {
				if len(m.Pseudo) == 0 {
					return errors.New("expected pseudo section")
				}
				s, ok := m.Pseudo[0].(*dns.SUBNET)
				if !ok {
					return errors.New("expected EDNS0 SUBNET")
				}
				const addr = "14.128.63.0"
				if s.Address != netip.MustParseAddr(addr) {
					return errors.New("expected address: " + addr)
				}
				return nil
			},
		},
		{
			"edns0-subnet",
			[]byte{255, 234, 0, 16, 0, 1, 0, 0, 0, 0, 0, 1, 7, 99, 111, 114, 101, 68, 110, 83, 2, 105, 111, 0, 0, 28, 0, 1, 0, 0, 41, 5, 120, 0, 0, 128, 0, 0, 11, 0, 8, 0, 7, 0, 1, 24, 0, 62, 212, 234},
			func(m *dns.Msg) error {
				if len(m.Pseudo) == 0 {
					return errors.New("expected pseudo section")
				}
				s, ok := m.Pseudo[0].(*dns.SUBNET)
				if !ok {
					return errors.New("expected EDNS0 SUBNET")
				}
				const addr = "62.212.234.0"
				if s.Address != netip.MustParseAddr(addr) {
					return errors.New("expected address: " + addr)
				}
				return nil
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			m := &dns.Msg{Data: tc.buf}
			if err := m.Unpack(); err != nil {
				t.Logf("%v\n", bin.Dump(m.Data))
				t.Fatal(err)
			}
			if err := tc.fn(m); err != nil {
				t.Logf("%s\n", bin.Dump(m.Data))
				t.Fatal(err)
			}
		})
	}
}

func TestMsgUnpackName(t *testing.T) {
	tcs := []struct {
		buf   []byte
		start int
		name  string
		off   int
	}{
		// miek.nl (4 miek 2 nl 0)
		{[]byte{4, 109, 105, 101, 107, 2, 110, 108, 0}, 0, "miek.nl.", 9},
		// beginning of a message, ID (98, 24),... then miek.nl as question = 0 15 (mx as type) and 0 01 as
		// class. But then 192 12 which is a pointer to miek.nl, so lets decode that.
		{[]byte{98, 24, 129, 128, 0, 1, 0, 5, 0, 0, 0, 1, 4, 109, 105, 101, 107, 2, 110, 108, 0, 0, 15, 0, 1, 192, 12, 0}, 25, "miek.nl.", 27},
	}
	for i, tc := range tcs {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			s := cryptobyte.String(tc.buf[tc.start:])
			sl := (len(s))
			name, err := unpack.Name(&s, tc.buf)
			if err != nil {
				t.Fatal(err)
			}
			if off := tc.start + sl - len(s); off != tc.off {
				t.Errorf("expected offset %d, got %d", tc.off, off)
			}
			if name != tc.name {
				t.Errorf("expected name %s, got %s", tc.name, name)
			}
		})
	}
}

func TestMsgExtendedRcode(t *testing.T) {
	// set extended rcode, pack the message, unpack it, could should still be there. This tests _a lot_ as and OPT rr is allocated
	// and packed. Also during unpack the opposite is done.
	m := &dns.Msg{MsgHeader: dns.MsgHeader{ID: 3}}
	m.Question = []dns.RR{&dns.MX{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET}}}
	m.Rcode = dns.RcodeBadTime

	m.Pack()
	r := new(dns.Msg)
	r.Data = m.Data
	r.Unpack()
	if r.Rcode != dns.RcodeBadTime {
		t.Errorf("expected %s, got %s", dns.RcodeToString[dns.RcodeBadTime], dns.RcodeToString[r.Rcode])
	}
}

func FuzzMsgPack(f *testing.F) {
	binaries := []string{"dig-mx-miek.nl", "dig+do+nsid-a-miek.nl"}
	for _, binary := range binaries {
		buf, _ := os.ReadFile("testdata/" + binary)
		f.Add(buf)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m := &dns.Msg{Data: b}
		m.Unpack()
	})
}
