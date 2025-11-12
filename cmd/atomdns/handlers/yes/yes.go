package yes

import (
	"context"
	"io"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
)

type Yes struct {
	Caa []string
	Ns  string
}

const ttl = 254

func (y *Yes) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		qname, qtype := dnsutil.Question(r)
		m := r.Copy()
		dnsutil.SetReply(m, r)
		m.Authoritative = true

		h := dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl}

		switch qtype {
		case dns.TypeA:
			rr := &dns.A{Hdr: h, A: dnstest.IPv4}
			m.Answer = append(m.Answer, rr)
		case dns.TypeAAAA:
			rr := &dns.AAAA{Hdr: h, AAAA: dnstest.IPv6}
			m.Answer = append(m.Answer, rr)
		case dns.TypeCAA:
			for i := range y.Caa {
				rr := &dns.CAA{Hdr: h, Flag: 128, Tag: "issue", Value: y.Caa[i]}
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeTXT:
			rr := &dns.TXT{Hdr: h, Txt: []string{"yes"}}
			m.Answer = append(m.Answer, rr)
		case dns.TypeNS:
			h.Name = dns.Zone(ctx)
			rr := &dns.NS{Hdr: h, Ns: y.Ns}
			m.Answer = append(m.Answer, rr)
		case dns.TypeSOA:
			h.Name = dns.Zone(ctx)
			soa := &dns.SOA{Hdr: h, Ns: y.Ns, Mbox: dnsutil.Join("hostmaster", dns.Zone(ctx)),
				Serial: uint32(time.Now().Unix()), Minttl: ttl, Refresh: 3600, Retry: 3600, Expire: 3600}
			m.Answer = append(m.Answer, soa)
		default: // nodata response
			h.Name = dns.Zone(ctx)
			soa := &dns.SOA{Hdr: h, Ns: y.Ns, Mbox: dnsutil.Join("hostmaster", dns.Zone(ctx)),
				Serial: uint32(time.Now().Unix()), Minttl: ttl, Refresh: 3600, Retry: 3600, Expire: 3600}
			m.Ns = append(m.Ns, soa)
		}

		m = dnsctx.Funcs(ctx, m)
		if err := m.Pack(); err != nil {
			log().Debug("Pack failure", Err(err))
		}
		io.Copy(w, m)
	})
}
