package any

import (
	"context"
	"io"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

type Any int

func (a *Any) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		if _, ok := r.Question[0].(*dns.ANY); !ok {
			next.ServeDNS(ctx, w, r)
			return
		}

		m := &dns.Msg{Data: r.Data} // reuse buffer
		dnsutil.SetReply(m, r)
		hdr := dns.Header{Name: r.Question[0].Header().Name, TTL: 8482, Class: dns.ClassINET}
		m.Answer = []dns.RR{&dns.HINFO{Hdr: hdr, Cpu: "ANY obsoleted", Os: "See RFC 8482"}}

		m.Pack()
		io.Copy(w, m)
	})
}
