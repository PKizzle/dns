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
	Caa     []string
	Sources []string
}

const ttl = 300

func (y *Yes) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		qname, qtype := dnsutil.Question(r)
		m := r.Copy()
		dnsutil.SetReply(m, r)
		m.Authoritative = true

		h := dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl}
		soa := &dns.SOA{Hdr: dns.Header{Name: dns.Zone(ctx), Class: dns.ClassINET, TTL: ttl},
			Ns: dnsutil.Join("ns", dns.Zone(ctx)), Mbox: dnsutil.Join("hostmaster", dns.Zone(ctx)),
			Serial: uint32(time.Now().Unix()), Minttl: ttl, Refresh: 3600, Retry: 3600, Expire: 3600}

		switch qtype {
		case dns.TypeA:
			addr := source(1, y.Sources)
			if addr != nil {
				rr := &dns.A{Hdr: h, A: addr}
				m.Answer = append(m.Answer, rr)
			} else {
				m.Ns = append(m.Ns, soa)
			}
		case dns.TypeAAAA:
			addr := source(2, y.Sources)
			if addr != nil {
				rr := &dns.AAAA{Hdr: h, AAAA: addr}
				m.Answer = append(m.Answer, rr)
			} else {
				m.Ns = append(m.Ns, soa)
			}
		case dns.TypeCAA:
			for i := range y.Caa {
				rr := &dns.CAA{Hdr: h, Flag: 128, Tag: "issuer", Value: y.Caa[i]}
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeNS:
			rr := &dns.NS{Hdr: dns.Header{Name: dnsutil.Join("ns", dns.Zone(ctx)), Class: dns.ClassINET, TTL: ttl}, Ns: dnsutil.Join("ns", dns.Zone(ctx))}
			m.Answer = append(m.Answer, rr)
		case dns.TypeSOA:
			m.Answer = append(m.Answer, soa)
		case dns.TypeTXT:
			rr := &dns.TXT{Hdr: h, Txt: []string{"yes"}}
			m.Answer = append(m.Answer, rr)
		default: // nodata response
			m.Ns = append(m.Ns, soa)
		}

		m = dnsctx.Funcs(ctx, m)
		if err := m.Pack(); err != nil {
			log().Debug("Pack failure", Err(err))
		}
		io.Copy(w, m)
	})
}

func source(fam int, sources []string) net.IP {
	for _, s := range sources {
		sip := net.ParseIP(s)
		if x := sip.To4(); x != nil && fam == 1 {
			return x
		}
		if sip.To4() == nil && fam == 2 {
			return sip
		}
	}
	return nil
}
