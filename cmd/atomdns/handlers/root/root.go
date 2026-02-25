package root

import "codeberg.org/miekg/dns"

type Root struct {
	old string
	cur string
}

func (r *Root) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc { return nil }
