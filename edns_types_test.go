package dns_test

import (
	"context"
	"io"
	"log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// This shows how to add an EDE error messsage to a reply.
func ExampleEDE() {
	// This is a dns.HandlerFunc for use in a dns.Server.
	_ = func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := r.Copy()
		dnsutil.SetReply(m, r)

		ede := &dns.EDE{InfoCode: dns.ExtendedErrorCensored}
		m.Pseudo = append(m.Pseudo, ede)

		if err := m.Pack(); err != nil {
			log.Println(err)
			return
		}
		io.Copy(w, m)
	}
}

// This shows how to add an NSID to a reply.
func ExampleNSID() {
	// This is a dns.HandlerFunc for use in a dns.Server.
	_ = func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := r.Copy()
		dnsutil.SetReply(m, r)

		nsid := &dns.NSID{Nsid: "its_me!"}
		m.Pseudo = append(m.Pseudo, nsid)

		if err := m.Pack(); err != nil {
			log.Println(err)
			return
		}
		io.Copy(w, m)
	}
}
