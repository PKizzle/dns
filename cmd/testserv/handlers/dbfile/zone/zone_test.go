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
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			expmsg := tc.exp()
			exprrs := []dns.RR{}
			for rr := range expmsg.All() {
				exprrs = append(exprrs, rr)
			}
			rmsg := z.Get(tc.in())
			i := 0
			for rr := range rmsg.All() {
				if !dns.Equal(rr, exprrs[i]) {
					t.Errorf("expected %s and %s to be equal", rr, exprrs[i])
				}
				i++
			}
		})
	}
}
