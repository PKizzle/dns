package dns_test

import (
	"fmt"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

const externalType = 65282

type externalRDATA struct {
	value  string
	origin string
}

func (rd externalRDATA) Len() int       { return len(rd.value) }
func (rd externalRDATA) String() string { return rd.value }

type externalRR struct {
	hdr  dns.Header
	data externalRDATA
}

func (rr *externalRR) Header() *dns.Header { return &rr.hdr }
func (rr *externalRR) Data() dns.RDATA     { return rr.data }
func (rr *externalRR) Len() int            { return rr.hdr.Len() + rr.data.Len() }
func (rr *externalRR) String() string      { return rr.data.String() }
func (rr *externalRR) Clone() dns.RR {
	clone := *rr
	return &clone
}
func (rr *externalRR) Parse(tokens []string, origin string) error {
	if len(tokens) != 1 {
		return fmt.Errorf("expected one token, got %d", len(tokens))
	}
	rr.data = externalRDATA{value: tokens[0], origin: origin}
	return nil
}

// Example on how get the text presentation of a [dns.RR].
func ExampleRDATA_string() {
	rr := &dns.MX{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET, TTL: 3600}, MX: rdata.MX{Preference: 10, Mx: "mx.miek.nl."}}
	s := rr.Header().String() + " " + dnsutil.TypeToString(dns.RRToType(rr)) + "\t" + rr.Data().String()
	fmt.Println(s)
	// Output: miek.nl.	3600	IN MX	10 mx.miek.nl.
}

// Example on how to set the rdata of an RR.
func ExampleRDATA_newData() {
	rd, _ := dns.NewData(dns.TypeMX, "10 mx.miek.nl.")
	rr := dns.TypeToRR[dns.TypeMX]()
	rr.Header().Name = "miek.nl."
	rr.Header().Class = dns.ClassINET
	fn := dns.TypeToRDATA[dns.TypeMX]
	// Set the rdata in the rr.
	fn(rr, rd)
	fmt.Println(rr)
	// Output: miek.nl.	0	IN	MX	10 mx.miek.nl.
}

func TestTypeToRDATA(t *testing.T) {
	testcases := []struct {
		name string
		t    uint16
		in   string
		fn   func(rr dns.RR) error
	}{
		{
			"mx",
			dns.TypeMX,
			"10 mx.miek.nl.",
			func(rr dns.RR) error {
				mx, ok := rr.(*dns.MX)
				if !ok {
					return fmt.Errorf("expected MX, got %T", rr)
				}
				if mx.Preference != 10 {
					return fmt.Errorf("expected 10, got %d", mx.Preference)
				}
				if mx.Mx != "mx.miek.nl." {
					return fmt.Errorf("expected mx.miek.nl., got %s", mx.Mx)
				}
				return nil
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			rd, _ := dns.NewData(tc.t, tc.in, ".")
			rr := dns.TypeToRR[tc.t]()
			fn := dns.TypeToRDATA[tc.t]
			fn(rr, rd)

		})
	}
}

func TestNewData(t *testing.T) {
	testcases := []struct {
		name string
		t    uint16
		in   string
		fn   func(rd dns.RDATA) error
	}{
		{
			"mx-origin-ok",
			dns.TypeMX,
			"10 mx.miek.nl",
			func(rd dns.RDATA) error {
				if rd == nil {
					return fmt.Errorf("expected rd, got none")
				}
				mx := rd.(rdata.MX)
				if mx.Preference != 10 {
					return fmt.Errorf("expected 10, got %d", mx.Preference)
				}
				if mx.Mx != "mx.miek.nl." {
					return fmt.Errorf("expected mx.miek.nl., got %s", mx.Mx)
				}
				return nil
			},
		},
		{
			"mx-ok",
			dns.TypeMX,
			"10 mx.miek.nl.",
			func(rd dns.RDATA) error {
				if rd == nil {
					return fmt.Errorf("expected rd, got none")
				}
				mx := rd.(rdata.MX)
				if mx.Preference != 10 {
					return fmt.Errorf("expected 10, got %d", mx.Preference)
				}
				if mx.Mx != "mx.miek.nl." {
					return fmt.Errorf("expected mx.miek.nl., got %s", mx.Mx)
				}
				return nil
			},
		},
		{
			"mx-space-fail",
			dns.TypeMX,
			" 10 mx.miek.nl.",
			func(rd dns.RDATA) error {
				if rd.(rdata.MX).Preference == 0 {
					return nil
				}
				return fmt.Errorf("expected nil rd: %v", rd)
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			rd, _ := dns.NewData(tc.t, tc.in, ".")
			if err := tc.fn(rd); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNewDataExternalParser(t *testing.T) {
	dns.TypeToRR[externalType] = func() dns.RR { return new(externalRR) }
	t.Cleanup(func() { delete(dns.TypeToRR, externalType) })

	rd, err := dns.NewData(externalType, "value", "example.org.")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := rd.(externalRDATA)
	if !ok {
		t.Fatalf("expected externalRDATA, got %T", rd)
	}
	if got.value != "value" {
		t.Errorf("expected value, got %q", got.value)
	}
	if got.origin != "example.org." {
		t.Errorf("expected origin example.org., got %q", got.origin)
	}
}
