package dns_test

import (
	"fmt"
	"strconv"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsfmt"
)

// YO is a private RR.
type YO struct {
	Hdr      dns.Header
	Priority uint8
	Yo       string `dns:"txt"`
}

const codepoint = 65281

// Typer interface.
func (rr *YO) Type() uint16 { return codepoint }

// RR interface.
func (rr *YO) Header() *dns.Header { return &rr.Hdr }
func (rr *YO) Len() int            { return rr.Hdr.Len() + 2 + len(rr.Yo) + 1 }
func (rr *YO) String() string      { return dnsfmt.Header(rr) + fmt.Sprintf("\t%d %s", rr.Priority, rr.Yo) }
func (rr *YO) Clone() dns.RR       { return &YO{rr.Hdr, rr.Priority, rr.Yo} }

// Parser interface.
func (rr *YO) Parse(o string, tokens []string) error {
	if len(tokens) < 2 { // no rdata
		return nil
	}
	i, err := strconv.ParseUint(tokens[0], 10, 32)
	if err != nil || i > 255 {
		return fmt.Errorf("bad YO Priority")
	}
	rr.Priority = uint8(i)
	rr.Yo = tokens[1]
	return nil
}

func TestExternalRR(t *testing.T) {
	dns.TypeToRR[codepoint] = func() dns.RR { return new(YO) }
	dns.TypeToString[codepoint] = "YO"
	dns.StringToType["YO"] = codepoint

	y := &YO{Hdr: dns.Header{Name: "example.org.", Class: dns.ClassINET}, Priority: 10, Yo: "Yo!"}
	rry, err := dns.New(y.String())
	if err != nil {
		t.Fatal(err)
	}
	if rry.String() != y.String() {
		t.Fatal("YO string presentations should be identical")
	}
}
