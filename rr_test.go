package dns_test

import (
	"fmt"
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

// Typer interface
func (rr *YO) Type() uint16 { return 65281 }

// RR interface
func (rr *YO) Header() *dns.Header { return &rr.Hdr }
func (rr *YO) Len() int            { return rr.Hdr.Len() + 2 + len(rr.Yo) + 1 }
func (rr *YO) String() string      { return dnsfmt.Header(rr) + fmt.Sprintf("\t%d %s", rr.Priority, rr.Yo) }
func (rr *YO) Clone() dns.RR       { return &YO{rr.Hdr, rr.Priority, rr.Yo} }

func TestExternalRR(t *testing.T) {
	dns.TypeToRR[65281] = func() dns.RR { return new(YO) }
	dns.TypeToString[65281] = "YO"

	y := &YO{Hdr: dns.Header{Name: "example.org.", Class: dns.ClassINET}, Priority: 10, Yo: "Yo!"}
	println(y.String())
	rry, err := dns.New(y.String())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(rry.String())
}
