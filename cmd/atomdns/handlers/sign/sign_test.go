package sign

import (
	"fmt"
	"slices"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func TestSign(t *testing.T) {
	dnszone := "miek.nl."
	config := `sign testdata/db.miek.nl {
        		key testdata/Kmiek.nl.+013+59725
	    	}`

	s := new(Sign)
	co := dnsserver.NewTestController(config)
	err := s.Setup(co)
	if err != nil {
		t.Fatal(err)
	}
	// because of NewTestController's way of working we miss sign.Zones map, because we don't have keys to add.
	s.Zones = map[string]*zone.Zone{dnszone: zone.New(dnszone, s.Path)}

	sz, err := s.Sign(dnszone)
	if err != nil {
		t.Fatal(err)
	}

	testcases := []struct {
		name string
		a    func() zone.Node
		b    func() zone.Node
		ok   func(a, b zone.Node) error
	}{
		{
			"nsec-chain",
			func() zone.Node { apex, _ := sz.Get(dnszone); return apex },
			func() zone.Node { next, _ := sz.Get("www." + dnszone); return next },
			func(a, b zone.Node) error {
				for _, rr := range a.RRs {
					if n, ok := rr.(*dns.NSEC); ok {
						if n.NextDomain != "a."+dnszone {
							return fmt.Errorf("next domain is not: %s", "a."+dnszone)
						}
					}
				}
				for _, rr := range b.RRs {
					if n, ok := rr.(*dns.NSEC); ok {
						if n.NextDomain != dnszone {
							return fmt.Errorf("next domain is wrapped back to: %s", dnszone)
						}
					}
				}
				return nil
			},
		},
		{
			"nsec-bitmap",
			func() zone.Node { apex, _ := sz.Get(dnszone); return apex },
			func() zone.Node { return zone.Node{} },
			func(a, b zone.Node) error {
				for _, rr := range a.RRs {
					exp := []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeMX, dns.TypeAAAA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY, dns.TypeCDS, dns.TypeCDNSKEY}
					if n, ok := rr.(*dns.NSEC); ok {
						if slices.Compare(n.TypeBitMap, exp) != 0 {
							return fmt.Errorf("type bitmap is not: %v", exp)
						}
					}
				}
				return nil
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ok(tc.a(), tc.b())
			if err != nil {
				t.Fatalf("expected no error, but got: %s", err)
			}
		})
	}
}
