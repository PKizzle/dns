package whoami

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnslog"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

type Whoami int

func (w *Whoami) HandlerFunc(_ dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		var rr dns.RR
		m := r.Copy()
		dnsutil.SetReply(m, r)

		var ip netip.Addr
		switch a := w.RemoteAddr().(type) {
		case *net.UDPAddr:
			ip = a.AddrPort().Addr()
		case *net.TCPAddr:
			ip = a.AddrPort().Addr()
		}

		if ip.Is4() {
			rr = &dns.A{Hdr: dns.Header{Name: r.Question[0].Header().Name, Class: dns.ClassINET}, A: rdata.A{Addr: ip}}
		} else {
			rr = &dns.AAAA{Hdr: dns.Header{Name: r.Question[0].Header().Name, Class: dns.ClassINET}, AAAA: rdata.AAAA{Addr: ip}}
		}

		port := dnsutil.RemotePort(w)
		network := dnsutil.Network(w)
		t := &dns.TXT{
			Hdr: dns.Header{Name: r.Question[0].Header().Name, Class: dns.ClassINET},
			TXT: rdata.TXT{Txt: []string{fmt.Sprintf("Port: %s (%s)", port, network)}},
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

		m = dnsctx.Funcs(ctx, m)
		if err := m.Pack(); err != nil {
			log().With(dnsctx.Id(ctx)).Debug(dnslog.PackFail, Err(err))
		}
		io.Copy(w, m)
	})
}
