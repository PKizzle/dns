package dns

import (
	"testing"

	"codeberg.org/miekg/dns/internal/pack"
)

// BenchmarkCreateMsg benchmarks the creation of a small Msg with a question section only.
func BenchmarkMakeMsgQuestionMX(b *testing.B) {
	for b.Loop() {
		msg := new(Msg)
		msg.ID = ID()
		msg.RecursionDesired = true
		msg.Question = []RR{&MX{Hdr: Header{Name: "miek.nl."}}}
		msg.Pack()
	}
}

func BenchmarkPackName(b *testing.B) {
	name := "my.testserver.l.miek.nl."
	buf := make([]byte, 30)
	for b.Loop() {
		pack.Name(name, buf, 0, nil, false)
	}
}

func BenchmarkUnPackName(b *testing.B) {
	m := &Msg{MsgHeader: MsgHeader{ID: 3, RecursionDesired: true}}
	mx := &MX{Hdr: Header{Name: "miek.nl.", Class: ClassINET}}
	m.Question = []RR{mx}
	m.Pack()
	// Output: [0 3 1 0 0 1 0 0 0 0 0 0 4 109 105 101 107 2 110 108 0 0 15 0 1]
	name, _, err := UnpackName(m.Data, 12)
	if err != nil {
		b.Fatal(err)
	}
	b.Logf("expected name: %s", name)

	for b.Loop() {
		UnpackName(m.Data, 12)
	}
}
