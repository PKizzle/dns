package zone

import (
	"sort"
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
				m.Answer[0] = dnstest.New("example.org.    1800    IN      NS      a.iana-servers.net.")
				m.Answer[1] = dnstest.New("example.org.    1800    IN      NS      b.iana-servers.net.")
				return m
			},
		},
		{
			"dns:exact",
			func() *dns.Msg { m := dns.NewMsg("a.example.org.", dns.TypeA); return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.example.org.", dns.TypeA)
				m.Answer = make([]dns.RR, 1)
				m.Answer[0] = dnstest.New("a.example.org.  1800    IN      A       139.162.196.78")
				return m
			},
		},
		{
			"dnssec:exact",
			func() *dns.Msg { m := dns.NewMsg("a.example.org.", dns.TypeA); m.Security = true; return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.example.org.", dns.TypeA)
				m.Answer = make([]dns.RR, 2)
				m.Answer[0] = dnstest.New("a.example.org.  1800    IN      A       139.162.196.78")
				m.Answer[1] = dnstest.New("a.example.org.  1800    IN      RRSIG   A 13 3 1800 20161129153240 20161030153240 49035 example.org. 41jFz0Dr8tZBN4Kv25S5dD4vTmviFiLx7xSAqMIuLFm0qibKL07perKpxqgLqM0H1wreT4xzI9Y4Dgp1nsOuMA==")
				return m
			},
		},
		{
			"dns:delegation",
			func() *dns.Msg { m := dns.NewMsg("a.delegated.example.org.", dns.TypeA); return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.delegated.example.org.", dns.TypeA)
				m.Answer = make([]dns.RR, 2)
				m.Answer[0] = dnstest.New("delegated.example.org.  1800    IN NS   a.delegated.example.org.")
				m.Answer[1] = dnstest.New("delegated.example.org.  1800    IN NS   ns-ext.nlnetlabs.nl.")
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
			allrrs := []dns.RR{}
			for rr := range rmsg.All() {
				allrrs = append(allrrs, rr)
			}
			sort.Sort(dns.RRset(allrrs))
			if len(exprrs) != len(allrrs) {
				t.Errorf("expected %d RRs, got %d", len(exprrs), len(allrrs))
			}
			for i := range allrrs {
				if !dns.Equal(allrrs[i], exprrs[i]) {
					t.Errorf("expected %s and %s to be equal", allrrs[i], exprrs[i])
				}
			}
		})
	}
}
