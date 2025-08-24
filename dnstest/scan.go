package dnstest

import "codeberg.org/miekg/dns"

// New calls [dns.New], but panics if an error is returned.
func New(s string) dns.RR {
	r, err := dns.New(s)
	if err != nil {
		panic("dnsutil: " + err.Error())
	}
	return r
}
