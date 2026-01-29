package dns

import (
	"fmt"
	"testing"

	"codeberg.org/miekg/dns/rdata"
	"github.com/miekg/dns"
)

func TestNewData(t *testing.T) {
	testcases := []struct {
		name string
		t    uint16
		in   string
		fn   func(rd RDATA) error
	}{
		{
			"mx-origin-ok",
			dns.TypeMX,
			"10 mx.miek.nl",
			func(rd RDATA) error {
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
			func(rd RDATA) error {
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
			func(rd RDATA) error {
				if rd == nil {
					return nil
				}
				return fmt.Errorf("expected nil rd")
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			rd, _ := NewData(tc.t, tc.in, ".")
			if err := tc.fn(rd); err != nil {
				t.Fatal(err)
			}
		})
	}
}
