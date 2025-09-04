// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// An AS112 blackhole DNS server. Similar to the one found in evldns.
// Also see https://www.as112.net/

package as112

import (
	"context"
	"io"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
)

type As112 int

const SOA string = "@ SOA prisoner.iana.org. hostmaster.root-servers.org. 2002040800 1800 900 0604800 604800"

var zones = map[string]dns.RR{
	"10.in-addr.arpa.":      dnstest.New("$ORIGIN 10.in-addr.arpa.\n" + SOA),
	"254.169.in-addr.arpa.": dnstest.New("$ORIGIN 254.169.in-addr.arpa.\n" + SOA),
	"168.192.in-addr.arpa.": dnstest.New("$ORIGIN 168.192.in-addr.arpa.\n" + SOA),
	"16.172.in-addr.arpa.":  dnstest.New("$ORIGIN 16.172.in-addr.arpa.\n" + SOA),
	"17.172.in-addr.arpa.":  dnstest.New("$ORIGIN 17.172.in-addr.arpa.\n" + SOA),
	"18.172.in-addr.arpa.":  dnstest.New("$ORIGIN 18.172.in-addr.arpa.\n" + SOA),
	"19.172.in-addr.arpa.":  dnstest.New("$ORIGIN 19.172.in-addr.arpa.\n" + SOA),
	"20.172.in-addr.arpa.":  dnstest.New("$ORIGIN 20.172.in-addr.arpa.\n" + SOA),
	"21.172.in-addr.arpa.":  dnstest.New("$ORIGIN 21.172.in-addr.arpa.\n" + SOA),
	"22.172.in-addr.arpa.":  dnstest.New("$ORIGIN 22.172.in-addr.arpa.\n" + SOA),
	"23.172.in-addr.arpa.":  dnstest.New("$ORIGIN 23.172.in-addr.arpa.\n" + SOA),
	"24.172.in-addr.arpa.":  dnstest.New("$ORIGIN 24.172.in-addr.arpa.\n" + SOA),
	"25.172.in-addr.arpa.":  dnstest.New("$ORIGIN 25.172.in-addr.arpa.\n" + SOA),
	"26.172.in-addr.arpa.":  dnstest.New("$ORIGIN 26.172.in-addr.arpa.\n" + SOA),
	"27.172.in-addr.arpa.":  dnstest.New("$ORIGIN 27.172.in-addr.arpa.\n" + SOA),
	"28.172.in-addr.arpa.":  dnstest.New("$ORIGIN 28.172.in-addr.arpa.\n" + SOA),
	"29.172.in-addr.arpa.":  dnstest.New("$ORIGIN 29.172.in-addr.arpa.\n" + SOA),
	"30.172.in-addr.arpa.":  dnstest.New("$ORIGIN 30.172.in-addr.arpa.\n" + SOA),
	"31.172.in-addr.arpa.":  dnstest.New("$ORIGIN 31.172.in-addr.arpa.\n" + SOA),
}

func (a *As112) HandlerFunc(_ dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		for z, rr := range zones {
			rrx := rr.(*dns.SOA) // Needed to create the actual RR, and not an reference.
			dns.HandleFunc(z, func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
				r.Unpack()

				m := new(dns.Msg)
				m.Data = r.Data
				dnsutil.SetReply(m, r)
				m.Authoritative = true
				m.Ns = []dns.RR{rrx}
				io.Copy(w, m)
			})
		}
	})
}
