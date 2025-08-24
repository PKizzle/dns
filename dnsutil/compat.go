package dnsutil

import "codeberg.org/miekg/dns"

// SetQuestion set the question section in the message m.
// It generates an ID and sets the RecursionDesired (RD) bit to true.
// If the type t isn't know, nil is returned.
func SetQuestion(m *dns.Msg, z string, t uint16) *dns.Msg {
	m.ID = dns.ID()
	m.RecursionDesired = true
	var rr dns.RR
	newFn, ok := dns.TypeToRR[t]
	if !ok {
		return nil
	}
	rr = newFn()
	rr.Header().Name = z
	rr.Header().Class = dns.ClassINET

	m.Question = []dns.RR{rr}
	return m
}

// Question return the question namd and the type from the message m.
func Question(m *dns.Msg) (z string, t uint16) {
	z = m.Question[0].Header().Name
	t = dns.RRToType(m.Question[0])
	return z, t
}

// SetIXFR creates message for requesting an IXFR.
func SetIXFR(m *dns.Msg, z string, serial uint32, ns, mbox string) *dns.Msg {
	m.ID = dns.ID()
	m = SetQuestion(m, z, dns.TypeIXFR)
	s := &dns.SOA{Hdr: dns.Header{Name: z, Class: dns.ClassINET}, Serial: serial, Ns: ns, Mbox: mbox}
	m.Ns = []dns.RR{s}
	return m
}

// SetAXFR creates message for requesting an AXFR.
func SetAXFR(m *dns.Msg, z string) *dns.Msg { return SetQuestion(m, z, dns.TypeAXFR) }
