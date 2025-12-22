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

// CUSTOMOPT is a custom EDNS0 option for testing external EDNS0 support.
// It demonstrates how to implement a custom EDNS0 option using the EDNS0Coder interface.
type CUSTOMOPT struct {
	Data string
}

const customOptCode = 0xFDE9 // Local/experimental use range

// EDNS0 interface (embedding RR) - these methods make it an RR
func (o *CUSTOMOPT) Header() *dns.Header { return &dns.Header{Name: "."} }
func (o *CUSTOMOPT) Pseudo() bool        { return true }
func (o *CUSTOMOPT) Len() int            { return 4 + len(o.Data) } // 4 = TLV overhead (code + length)
func (o *CUSTOMOPT) Clone() dns.RR {
	return &CUSTOMOPT{Data: o.Data}
}
func (o *CUSTOMOPT) String() string {
	return "CUSTOMOPT " + o.Data
}

// Typer interface - returns the EDNS0 option code
func (o *CUSTOMOPT) Type() uint16 { return customOptCode }

// EDNS0Coder interface - provides Pack/Unpack for wire format
// Pack only encodes the option data, not the TLV header
func (o *CUSTOMOPT) Pack(msg []byte, off int) (int, error) {
	if off+len(o.Data) > len(msg) {
		return len(msg), fmt.Errorf("overflow packing CUSTOMOPT")
	}
	copy(msg[off:], o.Data)
	return off + len(o.Data), nil
}

// Unpack decodes the option data from wire format
func (o *CUSTOMOPT) Unpack(s *cryptobyte.String) error {
	data := make([]byte, len(*s))
	if !s.CopyBytes(data) {
		return fmt.Errorf("overflow unpacking CUSTOMOPT")
	}
	o.Data = string(data)
	return nil
}

func TestExternalEDNS0(t *testing.T) {
	// Register the custom EDNS0 option
	dns.CodeToRR[customOptCode] = func() dns.EDNS0 { return new(CUSTOMOPT) }
	dns.CodeToString[customOptCode] = "CUSTOMOPT"

	// Create a message with custom EDNS0 option
	m := new(dns.Msg)
	dnsutil.SetQuestion(m, "example.org.", dns.TypeA)

	customOpt := &CUSTOMOPT{Data: "test-data"}

	// Add custom EDNS0 option directly to the Pseudo section
	// The Pack() method will automatically create an OPT record containing these options
	m.Pseudo = append(m.Pseudo, customOpt)

	// Pack the message
	if err := m.Pack(); err != nil {
		t.Fatalf("failed to pack message with custom EDNS0 option: %v", err)
	}

	// Unpack the message
	m2 := new(dns.Msg)
	m2.Data = m.Data
	if err := m2.Unpack(); err != nil {
		t.Fatalf("failed to unpack message with custom EDNS0 option: %v", err)
	}

	// Verify the custom option was preserved in Pseudo section
	if len(m2.Pseudo) != 1 {
		t.Fatalf("expected 1 pseudo record, got %d", len(m2.Pseudo))
	}

	customOpt2, ok := m2.Pseudo[0].(*CUSTOMOPT)
	if !ok {
		t.Fatalf("pseudo record is not CUSTOMOPT, got %T", m2.Pseudo[0])
	}

	if customOpt2.Data != "test-data" {
		t.Fatalf("expected Data='test-data', got Data='%s'", customOpt2.Data)
	}

	// Verify Type() returns correct code
	if customOpt2.Type() != customOptCode {
		t.Fatalf("expected Type()=%d, got %d", customOptCode, customOpt2.Type())
	}

	t.Logf("Successfully packed and unpacked custom EDNS0 option: %s", customOpt2.String())
}
