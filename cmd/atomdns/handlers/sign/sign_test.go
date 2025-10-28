package sign

import (
	"fmt"
	"slices"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
)

func TestSign(t *testing.T) {
	testzone := "miek.nl."
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
	s.Zones = map[string]*zone.Zone{testzone: zone.New(testzone, s.Path)}

	sz, err := s.Sign(testzone)
	if err != nil {
		t.Fatal(err)
	}

	testcases := []struct {
		name string
		a    func() *dnszone.Node
		b    func() *dnszone.Node
		ok   func(a, b *dnszone.Node) error
	}{
		{
			"nsec-chain",
			func() *dnszone.Node { apex, _ := sz.Get(testzone); return apex },
			func() *dnszone.Node { next, _ := sz.Get("www." + testzone); return next },
			func(a, b *dnszone.Node) error {
				for _, rr := range a.RRs {
					if n, ok := rr.(*dns.NSEC); ok {
						if n.NextDomain != "a."+testzone {
							return fmt.Errorf("next domain is not: %s", "a."+testzone)
						}
					}
				}
				for _, rr := range b.RRs {
					if n, ok := rr.(*dns.NSEC); ok {
						if n.NextDomain != testzone {
							return fmt.Errorf("next domain is wrapped back to: %s", testzone)
						}
					}
				}
				return nil
			},
		},
		{
			"nsec-bitmap",
			func() *dnszone.Node { apex, _ := sz.Get(testzone); return apex },
			func() *dnszone.Node { return &dnszone.Node{} },
			func(a, b *dnszone.Node) error {
				for _, rr := range a.RRs {
					exp := []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeMX, dns.TypeAAAA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY, dns.TypeCDS, dns.TypeCDNSKEY}
					if n, ok := rr.(*dns.NSEC); ok {
						if slices.Compare(n.TypeBitMap, exp) != 0 {
							return fmt.Errorf("type bitmap is not: %v != %v", exp, n.TypeBitMap)
						}
					}
				}
				return nil
			},
		},
		{
			"all-sig",
			func() *dnszone.Node { node, _ := sz.Get("a.miek.nl."); return node },
			func() *dnszone.Node { return &dnszone.Node{} },
			func(a, b *dnszone.Node) error {
				for _, rr := range a.RRs {
					if s, ok := rr.(*dns.RRSIG); ok {
						if s.Signature == "" {
							return fmt.Errorf("RRSIG does not have a signature: %s", s)
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
