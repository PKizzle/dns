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

	labels := z.Labels
	sosynthesis, encloser := zone.Node{}, zone.Node{} // source of synthesis and closes encloser RRset + names.
	// See dbfile/zone/retrieve.go
	qname := r.Question[0].Header().Name

	// Doing apex queries separate simplifies the loop below as we can not have delegation, wildcards, etc.
	if z.Labels == dnsutil.Labels(qname) {
		return z.MsgFound(r, z.Apex(), hintAnswer, re)
	}

	labels++
	hint := hintAnswer
	encloser = z.Apex()
Search:
	for i, start := dnsutil.Prev(qname, labels); !start; i, start = dnsutil.Prev(qname, labels) {
		node, ok := z.Get(qname[i:])
		if ok {
			encloser = node

			// Check for delegation, thus NS and (later) DELEG records. If this set contain NS records we have a delegation.
			for _, rr := range node.RRs {
				if _, ok := rr.(*dns.NS); ok {
					hint = hintDelegation
					break Search
				}
			}

		} else {

			// Skip a label to the right again and replace with '*', this should work by definition. If we
			// find a wildcard label here we keep track of what we found, but we need to search below to see
			// if there is a more specific match.
			j, _ := dnsutil.Next(qname[i:], 0)
			node, ok := z.Get("*." + qname[i+j:])
			if ok {
				sosynthesis = node
				hint = hintWildcard
			}
		}

		labels++
	}

	if hint == hintWildcard {
		return z.MsgSynthesize(r, sosynthesis, encloser, re)
	}

	return z.MsgFound(r, encloser, hint, re)
}
