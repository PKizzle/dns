package main

import (
	"context"
	"io"
	"math/rand"
	"os"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Chaos allows sndns to reply to CH TXT queries and return author or version information.
type Chaos struct {
	Version string
	Authors []string
}

func (c *Chaos) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		qclass := r.Question[0].Header().Class
		if qclass != dns.ClassCHAOS {
			next.ServeDNS(ctx, w, r)
			return
		}
		if _, ok := r.Question[0].(*dns.TXT); !ok {
			next.ServeDNS(ctx, w, r)
			return
		}

		qname := r.Question[0].Header().Name
		m := &dns.Msg{Data: r.Data} // reuse buffer
		dnsutil.SetReply(m, r)

		hdr := dns.Header{Name: qname, Class: dns.ClassCHAOS}
		switch dnsutil.Canonical(qname) {
		default:
			next.ServeDNS(ctx, w, r)
			return
		case "authors.bind.":
			rnd := rand.New(rand.NewSource(time.Now().Unix()))

			for _, i := range rnd.Perm(len(c.Authors)) {
				m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr, Txt: []string{c.Authors[i]}})
			}
		case "version.bind.", "version.server.":
			m.Answer = []dns.RR{&dns.TXT{Hdr: hdr, Txt: []string{c.Version}}}
		case "hostname.bind.", "id.server.":
			hostname, err := os.Hostname()
			if err != nil {
				hostname = "localhost"
			}
			m.Answer = []dns.RR{&dns.TXT{Hdr: hdr, Txt: []string{hostname}}}
		}
		m.Pack()
		io.Copy(w, m)
	})
}
