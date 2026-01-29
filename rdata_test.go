package dns_test

import (
	"fmt"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// Example on how get the text presentation of a [dns.RR].
func ExampleRDATA_string() {
	rr := &dns.MX{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET, TTL: 3600}, MX: rdata.MX{Preference: 10, Mx: "mx.miek.nl."}}
	s := rr.Header().String() + " " + dnsutil.TypeToString(dns.RRToType(rr)) + "\t" + rr.Data().String()
	fmt.Println(s)
	// Output: miek.nl.	3600	IN MX	10 mx.miek.nl.
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
