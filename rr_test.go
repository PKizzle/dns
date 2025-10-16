package dns_test

import (
	"fmt"
	"strconv"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"golang.org/x/crypto/cryptobyte"
)

// YO is a private RR: www.example.org. IN YO 10 Yo!
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
func (rr *YO) Len() int            { return rr.Hdr.Len() + 1 + len(rr.Yo) }
func (rr *YO) Clone() dns.RR       { return &YO{rr.Hdr, rr.Priority, rr.Yo} }
func (rr *YO) String() string {
	return rr.Header().Name + "\t" +
		strconv.FormatInt(int64(rr.Header().TTL), 10) + "\t" +
		dnsutil.ClassToString(rr.Header().Class) + "\tYO\t" +
		strconv.FormatUint(uint64(rr.Priority), 10) + " " + rr.Yo
}

// Packer interface
func (rr *YO) Pack(msg []byte, off int) (int, error) {
	if off+len(rr.Yo)+1 > len(msg) {
		return len(msg), fmt.Errorf("overflow packing YO")
	}
	msg[off] = rr.Priority
	off++
	copy(msg[off:off+len(rr.Yo)], rr.Yo)
	off += len(rr.Yo)
	return off, nil
}

func (rr *YO) Unpack(data []byte) error {
	s := cryptobyte.String(data)
	if !s.ReadUint8(&rr.Priority) {
		return fmt.Errorf("overflow unpacking YO")
	}
	var b []byte
	if !s.ReadBytes(&b, len(s)) {
		return fmt.Errorf("overflow unpacking YO")
	}
	rr.Yo = string(b)
	if !s.Empty() {
		return fmt.Errorf("trailing record data: %s", "YO")
	}
	return nil
}

// Parser interface.
func (rr *YO) Parse(tokens []string, _ string) error {
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

	m := dns.NewMsg("yo.example.org.", codepoint)
	m.Answer = []dns.RR{y}
	m.Pack()
	r := new(dns.Msg)
	r.Data = m.Data
	r.Unpack()

	if m.String() != r.String() {
		t.Fatal("YO presentation should survive Pack/Unpack")
	}
}
