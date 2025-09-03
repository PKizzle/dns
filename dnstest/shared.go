package dnstest

import "codeberg.org/miekg/dns"

// This is copied to zdnstest.go in the main package to also have access to these functions and not have an
// import cycle. See dnstest_generate.go.

// New calls [dns.New], but panics if an error is returned.
func New(s string) dns.RR {
	r, err := dns.New(s)
	if err != nil {
		panic("dnsutil: " + err.Error())
	}
	return r
}
