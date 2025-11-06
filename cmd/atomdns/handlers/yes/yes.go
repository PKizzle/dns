package yes

import (
	"context"
	"io"
	"net"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/dnsutil"
)

type Yes struct {
	Caa []string
}

const ttl = 300

func (y *Yes) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		qname, qtype := dnsutil.Question(r)
		m := r.Copy()
		dnsutil.SetReply(m, r)
		m.Authoritative = true

		h := dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl}

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
		case dns.TypeNS:
			rr := &dns.NS{Hdr: dns.Header{Name: dnsutil.Join("ns", dns.Zone(ctx)), Class: dns.ClassINET, TTL: ttl}, Ns: dnsutil.Join("ns", dns.Zone(ctx))}
			m.Answer = append(m.Answer, rr)
		case dns.TypeSOA:
			rr := &dns.SOA{Hdr: dns.Header{Name: dns.Zone(ctx), Class: dns.ClassINET, TTL: ttl},
				Ns: dnsutil.Join("ns", dns.Zone(ctx)), Mbox: dnsutil.Join("hostmaster", dns.Zone(ctx)),
				Serial: uint32(time.Now().Unix()), Minttl: ttl, Refresh: 3600, Retry: 3600, Expire: 3600}
			m.Answer = append(m.Answer, rr)
		default: // nodata response
			rr := &dns.SOA{Hdr: dns.Header{Name: dns.Zone(ctx), Class: dns.ClassINET, TTL: ttl},
				Ns: dnsutil.Join("ns", dns.Zone(ctx)), Mbox: dnsutil.Join("hostmaster", dns.Zone(ctx)),
				Serial: uint32(time.Now().Unix()), Minttl: ttl, Refresh: 3600, Retry: 3600, Expire: 3600}
			m.Ns = append(m.Ns, rr)
		}

		m = dnsctx.Funcs(ctx, m)
		if err := m.Pack(); err != nil {
			log().Debug("Pack failure", Err(err))
		}
		io.Copy(w, m)
	})
}
