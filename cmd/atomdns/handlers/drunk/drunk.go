package drunk

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsmsg"
	"codeberg.org/miekg/dns/dnsutil"
)

type Drunk struct {
	i        uint64 // counter of queries
	drop     uint64
	delay    uint64
	truncate uint64

	duration time.Duration
}

func (d *Drunk) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		i := atomic.LoadUint64(&d.i)
		atomic.AddUint64(&d.i, 1)

		drop := d.drop > 0 && i%d.drop == 0
		delay := d.delay > 0 && i%d.delay == 0
		trunc := d.truncate > 0 && i&d.truncate == 0

		m := new(dns.Msg)
		dnsutil.SetReply(m, r)
		m.Authoritative = true
		m.Truncated = trunc

		switch r.Question[0].(type) {
		case *dns.A:
			rr := &dns.A{Hdr: dns.Header{Name: r.Question[0].Header().Name, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.53")}
			m.Answer = []dns.RR{rr}
		case *dns.AAAA:
			rr := &dns.AAAA{Hdr: dns.Header{Name: r.Question[0].Header().Name, Class: dns.ClassINET}, AAAA: net.ParseIP("2001:DB8::53")}
			m.Answer = []dns.RR{rr}
		default:
			if drop {
				log.Debug("Dropping")
				return
			}
			if delay {
				log.Debug("Delaying", slog.Duration("delay", d.duration))
				time.Sleep(d.duration)
			}
			next.ServeDNS(ctx, w, r)
			return
		}

		if drop {
			log.Debug("Dropping")
			return
		}
		if delay {
			log.Debug("Delaying", slog.Duration("delay", d.duration))
			time.Sleep(d.duration)
		}

		m.Data = r.Data

		m = dnsmsg.Funcs(ctx, m)
		if err := m.Pack(); err != nil {
			log.Debug("Pack failure", Err(err))
		}
		io.Copy(w, m)
	})
}
