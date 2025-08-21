package main

import (
	"context"
	"io"
	"log"
	"net"
	"strconv"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

type Whoami int

func (w *Whoami) HandlerFunc(_ dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		var (
			v4  bool
			rr  dns.RR
			str string
			a   net.IP
		)
		if err := r.Unpack(); err != nil {
			log.Fatalf("%s", err.Error())
		}
		m := new(dns.Msg)
		dnsutil.SetReply(m, r)

		if ip, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			str = "Port: " + strconv.Itoa(ip.Port) + " (udp)"
			a = ip.IP
			v4 = a.To4() != nil
		}
		if ip, ok := w.RemoteAddr().(*net.TCPAddr); ok {
			str = "Port: " + strconv.Itoa(ip.Port) + " (tcp)"
			a = ip.IP
			v4 = a.To4() != nil
		}

		if v4 {
			rr = &dns.A{Hdr: dns.Header{Name: r.Question[0].Header().Name, Class: dns.ClassINET}, A: a.To4()}
		} else {
			rr = &dns.AAAA{Hdr: dns.Header{Name: r.Question[0].Header().Name, Class: dns.ClassINET}, AAAA: a}
		}

		t := &dns.TXT{Hdr: dns.Header{Name: r.Question[0].Header().Name, Class: dns.ClassINET}, Txt: []string{str}}

		switch r.Question[0].(type) {
		case *dns.TXT:
			m.Answer = append(m.Answer, t)
			m.Extra = append(m.Extra, rr)
		case *dns.AAAA, *dns.A:
			m.Answer = append(m.Answer, rr)
			m.Extra = append(m.Extra, t)
		}

		io.Copy(w, m)
	})
}
