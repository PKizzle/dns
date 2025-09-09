package zone

import (
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
)

func TestZone(t *testing.T) {
	z, err := Load("example.org.", "testdata/db.example.org")
	if err != nil {
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
				m.Answer = make([]dns.RR, 2)
				m.Answer[0] = dnstest.New("example.org.    IN NS      a.iana-servers.net.")
				m.Answer[1] = dnstest.New("example.org.    IN NS      b.iana-servers.net.")
				return m
			},
		},
		{
			"dns:exact",
			func() *dns.Msg { m := dns.NewMsg("a.example.org.", dns.TypeA); return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.example.org.", dns.TypeA)
				m.Answer = make([]dns.RR, 1)
				m.Answer[0] = dnstest.New("a.example.org.  IN A       139.162.196.78")
				return m
			},
		},
		{
			"dnssec:exact",
			func() *dns.Msg { m := dns.NewMsg("a.example.org.", dns.TypeA); m.Security = true; return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.example.org.", dns.TypeA)
				m.Answer = make([]dns.RR, 2)
				m.Answer[0] = dnstest.New("a.example.org.  IN A       139.162.196.78")
				m.Answer[1] = dnstest.New("a.example.org.  IN RRSIG   A 13 3 1800 20161129153240 20161030153240 49035 example.org. 41jFz0Dr8tZBN4Kv25S5dD4vTmviFiLx7xSAqMIuLFm0qibKL07perKpxqgLqM0H1wreT4xzI9Y4Dgp1nsOuMA==")
				return m
			},
		},
		{
			"dns:delegation",
			func() *dns.Msg { m := dns.NewMsg("a.delegated.example.org.", dns.TypeA); return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.delegated.example.org.", dns.TypeA)
				m.Ns = make([]dns.RR, 2)
				m.Ns[0] = dnstest.New("delegated.example.org.  IN NS   a.delegated.example.org.")
				m.Ns[1] = dnstest.New("delegated.example.org.  IN NS   ns-ext.nlnetlabs.nl.")
				return m
			},
		},
		{
			"dnssec:delegation",
			func() *dns.Msg { m := dns.NewMsg("a.delegated.example.org.", dns.TypeA); m.Security = true; return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.delegated.example.org.", dns.TypeA)
				m.Ns = make([]dns.RR, 5)
				m.Ns[0] = dnstest.New("delegated.example.org.  IN NS   a.delegated.example.org.")
				m.Ns[1] = dnstest.New("delegated.example.org.  IN NS   ns-ext.nlnetlabs.nl.")
				m.Ns[2] = dnstest.New("delegated.example.org. IN DS	10056 5 1 EE72CABD1927759CDDA92A10DBF431504B9E1F13")
				m.Ns[3] = dnstest.New("delegated.example.org. IN DS	10056 5 2 E4B05F87725FA86D9A64F1E53C3D0E6250946599DFE639C45955B0ED416CDDFA")
				m.Ns[4] = dnstest.New("delegated.example.org. IN RRSIG	DS 13 3 1800 20161129153240 20161030153240 49035 example.org. rlNNzcUmtbjLSl02ZzQGUbWX75yCUx0Mug1jHtKVqRq1hpPE2S3863tIWSlz+W9wz4o19OI4jbznKKqk+DGKog==")
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
			//			sort.Sort(dns.RRset(gotrrs))
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
