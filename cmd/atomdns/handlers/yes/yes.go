package yes

import (
	"context"
	"io"
	"net"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/dnsutil"
)

type Yes struct {
	Caa []string
}

func (y *Yes) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		qname, qtype := dnsutil.Question(r)
		if qtype != dns.TypeA && qtype != dns.TypeAAAA && qtype != dns.TypeCAA {
			next.ServeDNS(ctx, w, r)
			return
		}
		m := r.Copy()
		dnsutil.SetReply(m, r)

		h := dns.Header{Name: qname, Class: dns.ClassINET, TTL: 1024}
		switch qtype {
		case dns.TypeA:
			rr := &dns.A{Hdr: h, A: net.ParseIP("198.51.100.1")}
			m.Answer = append(m.Answer, rr)
		case dns.TypeAAAA:
			rr := &dns.AAAA{Hdr: h, AAAA: net.ParseIP("2001:db8::1")}
			m.Answer = append(m.Answer, rr)
		case dns.TypeCAA:
			for i := range y.Caa {
				rr := &dns.CAA{Hdr: h, Flag: 128, Tag: "issuer", Value: y.Caa[i]}
				m.Answer = append(m.Answer, rr)
			}
		}

		m = dnsctx.Funcs(ctx, m)
		if err := m.Pack(); err != nil {
			log().Debug("Pack failure", Err(err))
		}
		io.Copy(w, m)
	})
}
