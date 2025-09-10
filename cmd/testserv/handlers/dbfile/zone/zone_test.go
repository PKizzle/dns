package zone

import (
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
)

func TestZone(t *testing.T) {
	z := New("example.org.", "testdata/db.example.org")
	if err := z.Load(); err != nil {
		t.Fatal(err)
	}
	testcases := []struct {
		name string
		in   func() *dns.Msg
		exp  func() *dns.Msg
	}{
		{
			"dns:apex",
			func() *dns.Msg { m := dns.NewMsg("example.org.", dns.TypeNS); return m },
			func() *dns.Msg {
				m := dns.NewMsg("example.org.", dns.TypeNS)
				m.Answer = []dns.RR{
					dnstest.New("example.org.    IN NS      a.iana-servers.net."),
					dnstest.New("example.org.    IN NS      b.iana-servers.net."),
				}
				return m
			},
		},
		{
			"dns:exact",
			func() *dns.Msg { m := dns.NewMsg("a.example.org.", dns.TypeA); return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.example.org.", dns.TypeA)
				m.Answer = []dns.RR{
					dnstest.New("a.example.org.  IN A       139.162.196.78"),
				}
				return m
			},
		},
		{
			"dnssec:exact",
			func() *dns.Msg { m := dns.NewMsg("a.example.org.", dns.TypeA); m.Security = true; return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.example.org.", dns.TypeA)
				m.Answer = []dns.RR{
					dnstest.New("a.example.org.  IN A       139.162.196.78"),
					dnstest.New("a.example.org.  IN RRSIG   A 13 3 1800 20161129153240 20161030153240 49035 example.org. 41jFz0Dr8tZBN4Kv25S5dD4vTmviFiLx7xSAqMIuLFm0qibKL07perKpxqgLqM0H1wreT4xzI9Y4Dgp1nsOuMA=="),
				}
				return m
			},
		},
		{
			"dns:delegation",
			func() *dns.Msg { m := dns.NewMsg("a.delegated.example.org.", dns.TypeA); return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.delegated.example.org.", dns.TypeA)
				m.Ns = []dns.RR{
					dnstest.New("delegated.example.org.  IN NS   a.delegated.example.org."),
					dnstest.New("delegated.example.org.  IN NS   ns-ext.nlnetlabs.nl."),
				}
				return m
			},
		},
		{
			"dnssec:delegation",
			func() *dns.Msg { m := dns.NewMsg("a.delegated.example.org.", dns.TypeA); m.Security = true; return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.delegated.example.org.", dns.TypeA)
				m.Ns = []dns.RR{
					dnstest.New("delegated.example.org. IN NS     a.delegated.example.org."),
					dnstest.New("delegated.example.org. IN NS     ns-ext.nlnetlabs.nl."),
					dnstest.New("delegated.example.org. IN DS	  10056 5 1 EE72CABD1927759CDDA92A10DBF431504B9E1F13"),
					dnstest.New("delegated.example.org. IN DS	  10056 5 2 E4B05F87725FA86D9A64F1E53C3D0E6250946599DFE639C45955B0ED416CDDFA"),
					dnstest.New("delegated.example.org. IN RRSIG   DS 13 3 1800 20161129153240 20161030153240 49035 example.org. rlNNzcUmtbjLSl02ZzQGUbWX75yCUx0Mug1jHtKVqRq1hpPE2S3863tIWSlz+W9wz4o19OI4jbznKKqk+DGKog=="),
				}
				return m
			},
		},
		{
			"dns:nodata",
			func() *dns.Msg { m := dns.NewMsg("a.example.org.", dns.TypeTXT); return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.example.org.", dns.TypeTXT)
				m.Answer = []dns.RR{
					dnstest.New("example.org. IN SOA  a.iana-servers.net. devnull.example.org. 1282630057 14400 3600 604800 14400"),
				}
				return m
			},
		},
		{
			"dnssec:nodata",
			func() *dns.Msg { m := dns.NewMsg("a.example.org.", dns.TypeTXT); m.Security = true; return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.example.org.", dns.TypeTXT)
				m.Answer = []dns.RR{
					dnstest.New("example.org. IN SOA     a.iana-servers.net. devnull.example.org. 1282630057 14400 3600 604800 14400"),
					dnstest.New("example.org. IN RRSIG   SOA 13 2 1800 20161129153240 20161030153240 49035 example.org. GVnMpFmN+6PDdgCtlYDEYBsnBNDgYmEJNvosBk9+PNTPNWNst+BXCpDadTeqRwrr1RHEAQ7jYWzNwqn81pN+IA=="),
					dnstest.New("example.org. IN NSEC    a.example.org. NS SOA RRSIG NSEC DNSKEY"),
					dnstest.New("example.org. IN RRSIG   NSEC 13 2 14400 20161129153240 20161030153240 49035 example.org. BQROf1swrmYi3GqpP5M/h5vTB8jmJ/RFnlaX7fjxvV7aMvXCsr3ekWeB2S7L6wWFihDYcKJg9BxVPqxzBKeaqg=="),
				}
				return m
			},
		},
		{
			"dns:nxdomain",
			func() *dns.Msg { m := dns.NewMsg("www1.example.org.", dns.TypeA); return m },
			func() *dns.Msg {
				m := dns.NewMsg("www1.example.org.", dns.TypeA)
				m.Answer = []dns.RR{
					dnstest.New("example.org. IN SOA  a.iana-servers.net. devnull.example.org. 1282630057 14400 3600 604800 14400"),
				}
				return m
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			expmsg := tc.exp()
			exprrs := []dns.RR{}
			for rr := range expmsg.All() {
				exprrs = append(exprrs, rr)
			}

			rmsg := z.Get(tc.in())
			gotrrs := []dns.RR{}
			for rr := range rmsg.All() {
				gotrrs = append(gotrrs, rr)
			}
			if len(exprrs) != len(gotrrs) {
				t.Errorf("expected %d RRs, got %d", len(exprrs), len(gotrrs))
				t.Logf("%s\n", rmsg)
			}
			for i := range gotrrs {
				if !dns.Equal(gotrrs[i], gotrrs[i]) {
					t.Errorf("expected %s and %s to be equal", gotrrs[i], exprrs[i])
				}
			}
		})
	}
}

// Needs a signed test zone that is also loaded in nsd with multi-level wildcard, of the various types.
func testZoneWildcard(t *testing.T) {
	z := New("dnssex.nl.", "testdata/db.dnssex.nl")
	if err := z.Load(); err != nil {
		t.Fatal(err)
	}
	testcases := []struct {
		name string
		in   func() *dns.Msg
		exp  func() *dns.Msg
	}{
		{
			"dns:exact",
			func() *dns.Msg { m := dns.NewMsg("dnssex.nl.", dns.TypeA); return m },
			func() *dns.Msg {
				m := dns.NewMsg("dnssex.nl.", dns.TypeA)
				m.Answer = []dns.RR{
					dnstest.New("dnssex.nl. IN A    139.162.196.78"),
				}
				return m
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			expmsg := tc.exp()
			exprrs := []dns.RR{}
			for rr := range expmsg.All() {
				exprrs = append(exprrs, rr)
			}

			rmsg := z.Get(tc.in())
			gotrrs := []dns.RR{}
			for rr := range rmsg.All() {
				gotrrs = append(gotrrs, rr)
			}
			if len(exprrs) != len(gotrrs) {
				t.Errorf("expected %d RRs, got %d", len(exprrs), len(gotrrs))
				t.Logf("%s\n", rmsg)
			}
			for i := range gotrrs {
				if !dns.Equal(gotrrs[i], gotrrs[i]) {
					t.Errorf("expected %s and %s to be equal", gotrrs[i], exprrs[i])
				}
			}
		})
	}
}
