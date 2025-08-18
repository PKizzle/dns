package dns_test

import (
	"fmt"
	"os"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/internal/bin"
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
	// TODO: turn into test
	binaries := []string{"dig-mx-miek.nl", "dig+do+nsid-a-miek.nl"}
	for i, binary := range binaries {
		t.Run(fmt.Sprintf("test %d: %s", i, binary), func(t *testing.T) {
			buf, _ := os.ReadFile("testdata/" + binary)
			m := &dns.Msg{Data: buf}
			if err := m.Unpack(); err != nil {
				t.Errorf("%s", err)
				t.Logf("%v\n", m.Data)
			}
			t.Logf("%s\n", m)
			t.Logf("%s\n", bin.Dump(m.Data))
		})
	}
}

func TestMsgPackBinary(t *testing.T) {
	// TODO: turn into test
	m := &dns.Msg{MsgHeader: dns.MsgHeader{ID: 3, RecursionDesired: true, Security: true, UDPSize: 1024}, Answer: make([]dns.RR, 2)}
	a := &dns.A{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET}}
	m.Question = []dns.RR{a}
	m.Pseudo = []dns.RR{&dns.NSID{Nsid: "6770"}}
	m.Answer[0], _ = dns.New("miek.nl.        14301   IN      A       45.138.52.215")
	m.Answer[1], _ = dns.New("miek.nl.        14301   IN      A       45.138.52.216")

	t.Logf("%s\n", m)
	m.Pack()
	t.Logf("%s\n", m)
}

func TestUnpackName(t *testing.T) {
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
			name, off, err := dns.UnpackName(tc.buf, tc.start)
			if err != nil {
				t.Fatal(err)
			}
			if name != tc.name {
				t.Errorf("expected name %s, got %s", tc.name, name)
			}
			if off != tc.off {
				t.Errorf("expected offset %d, got %d", tc.off, off)
			}
		})
	}
}

func TestMsgExtendedRcode(t *testing.T) {
	m := &dns.Msg{MsgHeader: dns.MsgHeader{ID: 3}}
	m.Question = []dns.RR{&dns.MX{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET}}}
	m.Rcode = dns.RcodeFormatError

	//m.Rcode = dns.RcodeBadCookie
	m.Rcode = dns.RcodeBadTime

	fmt.Printf("%s\n", m)
	m.Pack()
	m.Rcode = 0

	t.Logf("\n%s\n", bin.Dump(m.Data))

	m.Unpack()
	t.Logf("%s\n%s\n", m, bin.Dump(m.Data))
}
