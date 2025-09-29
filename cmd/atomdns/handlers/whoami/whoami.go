package whoami

import (
	"context"
	"fmt"
	"io"
	"net"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsmsg"
	"codeberg.org/miekg/dns/dnsutil"
)

type Whoami int

func (w *Whoami) HandlerFunc(_ dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		var rr dns.RR
		m := r.Copy()
		dnsutil.SetReply(m, r)

		family := dnsutil.Family(w)
		if family == 1 {
			rr = &dns.A{Hdr: dns.Header{Name: r.Question[0].Header().Name, Class: dns.ClassINET}, A: net.ParseIP(dnsutil.RemoteIP(w)).To4()}
		} else {
			rr = &dns.AAAA{Hdr: dns.Header{Name: r.Question[0].Header().Name, Class: dns.ClassINET}, AAAA: net.ParseIP(dnsutil.RemoteIP(w))}
		}

		port := dnsutil.RemotePort(w)
		network := dnsutil.Network(w)
		t := &dns.TXT{
			Hdr: dns.Header{Name: r.Question[0].Header().Name, Class: dns.ClassINET},
			Txt: []string{fmt.Sprintf("Port: %s (%s)", port, network)},
		}

		switch r.Question[0].(type) {
		case *dns.TXT:
			m.Answer = []dns.RR{t}
			m.Extra = []dns.RR{rr}
		case *dns.AAAA, *dns.A:
			m.Answer = []dns.RR{rr}
			m.Extra = []dns.RR{t}
		default:
			m.Rcode = dns.RcodeRefused
		}

		m = dnsmsg.Funcs(ctx, m)
		if err := m.Pack(); err != nil {
			log.Debug("Pack failure", Err(err))
		}
		io.Copy(w, m)
	})
}
