package dbsqlite

import (
	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
	"codeberg.org/miekg/dns/dnsutil"
)

type Hint int

const (
	hintAnswer Hint = iota
	hintDelegation
	hintWildcard
)

func (z *Zone) Retrieve(m *dns.Msg, re *zone.Restart) *dns.Msg {
	r := new(dns.Msg)
	dnsutil.SetReply(r, m)

	// labels := z.Labels
	// See dbfile/zone/retrieve.go
	qname := r.Question[0].Header().Name

	// Doing apex queries separate simplifies the loop below as we can not have delegation, wildcards, etc.
	if z.Labels == dnsutil.Labels(qname) {
		// return z.MsgFound(r, z.Apex(), hintAnswer, re)
	}
	return r
}
