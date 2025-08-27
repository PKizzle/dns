package dnsutil

import "codeberg.org/miekg/dns"

// SetQuestion set the question section in the message m.
// It generates an ID and sets the RecursionDesired (RD) bit to true.
// If the type t isn't know, nil is returned. Also see [dns.NewMsg].
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

// Question return the question name and the type from the message m.
func Question(m *dns.Msg) (z string, t uint16) {
	z = m.Question[0].Header().Name
	t = dns.RRToType(m.Question[0])
	return z, t
}
