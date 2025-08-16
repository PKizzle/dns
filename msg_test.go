package dns

import (
	"fmt"
	"os"
	"testing"
)

// TestMakeMsg_Question tests the creation of a small Msg with a question section only, and no EDNS0. This
// checks if we create the correct wire-format.
func ExampleMsg_Question() {
	m := &Msg{MsgHeader: MsgHeader{ID: 3, RecursionDesired: true}}
	mx := &MX{Hdr: Header{Name: "miek.nl.", Class: ClassINET}}
	m.Question = []RR{mx}

	m.Pack()
	fmt.Printf("%v\n", m.Data)
	// Output: [0 3 1 0 0 1 0 0 0 0 0 0 4 109 105 101 107 2 110 108 0 0 15 0 1]
}

func ExampleMsg_Pseudo_nsid() {
	m := &Msg{MsgHeader: MsgHeader{ID: 3, RecursionDesired: true}}
	m.Question = []RR{&MX{Hdr: Header{Name: "miek.nl.", Class: ClassINET}}}
	m.Pseudo = []RR{&NSID{}}

	m.Pack()
	// 41 is OPT after the zeros, 04 -> rdlength, 03 -> code of NSID, 00 -> "rdlength" of NSID
	fmt.Printf("%v\n", m.Data)
	// Output: [0 3 1 0 0 1 0 0 0 0 0 1 4 109 105 101 107 2 110 108 0 0 15 0 1 0 0 41 0 0 0 0 0 0 0 4 0 3 0 0]
}

func TestReadMsgBinary(t *testing.T) {
	// TODO: turn into test
	binary := []string{"dig-mx-miek.nl", "dig+do+nsid-a-miek.nl"}
	for i, bin := range binary {
		t.Run(fmt.Sprintf("test %d: %s", i, bin), func(t *testing.T) {
			buf, _ := os.ReadFile("testdata/" + bin)
			msg := &Msg{Data: buf}
			if err := msg.Unpack(); err != nil {
				t.Logf("%v\n", msg.Data)
				t.Errorf("%s", err)
			}
			t.Logf("%s\n", msg)
		})
	}
}

func TestPackPackBinary(t *testing.T) {
	msg := &Msg{MsgHeader: MsgHeader{ID: 3, RecursionDesired: true, Security: true, UDPSize: 1024}, Answer: make([]RR, 2)}
	a := &A{Hdr: Header{Name: "miek.nl.", Class: ClassINET}}
	msg.Question = []RR{a}
	msg.Pseudo = []RR{&NSID{Nsid: "6770"}}
	msg.Answer[0], _ = New("miek.nl.        14301   IN      A       45.138.52.215")
	msg.Answer[1], _ = New("miek.nl.        14301   IN      A       45.138.52.216")

	t.Logf("%s\n", msg)
	msg.Pack()
	t.Logf("%s\n", msg)
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
			name, off, err := UnpackName(tc.buf, tc.start)
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
