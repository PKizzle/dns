// Package implement a DNS zone, held in a binary tree. Each RR(set) that gets inserted will need to create
// any empty non-terminals (ENT) it possesses. I.e. inserting www.example.org into example.org is easy, but when
// www.a.b.c.example.org inserts we need to make sure that 'c.example.org', 'b.c.example.org' and
// 'a.b.c.example.org' also exist and are ENTs (have no actual RRs). For deleted the opposite must happen. As
// an example from RFC 4592, the record:  sub.*.example.  TXT  "this is not a wildcard" is a fun one. As this
// means the '*.example' ENT exists meaning that bogus.example. gets a NODATA response instead of NXDOMAIN.
//
// Doing this on insert sucks a bit, but makes the lookup code much more simple (and correct), which is more
// important for a DNS server.
package zone

import (
	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
	"codeberg.org/miekg/dns/dnsutil"
)

// Retrieve looks up the qname and qtype in the Zone z. It returns a message with the RRs (if found) in the
// correct places. In case of NXDOMAIN or NODATA response the message will also contain the correct
// information. The optional Restart is used to generate the correct CNAME chains.
// When calling Retrieve for the first time re should be nil.
func (z *Zone) Retrieve(m *dns.Msg, re *dnszone.Restart) *dns.Msg {
	// If here, we are guaranteed that this zone has the correct origin and the qname falls in this zone.
	// so we should be able to Prev to the first label that should fall in this zone.
	r := new(dns.Msg)
	dnsutil.SetReply(r, m)

	labels := z.Labels
	sosynthesis, encloser := dnszone.Node{}, dnszone.Node{} // source of synthesis and closes encloser RRset + names.

	// We have 2 loops, the Search loop and then a "found" loop. The search loop lookups up the correct
	// record set from the zone. The second loop (in z.Msg) then creates a message with the correct RRs in the sections.
	// This might involve even more zone lookups for cname and glue records. The returned message can be written to the client.
	qname := r.Question[0].Header().Name

	// Doing apex queries separate simplifies the loop below as we can not have delegation, wildcards, etc.
	if z.Labels == dnsutil.Labels(qname) {
		return dnszone.MsgFound(z, r, z.Apex(), dnszone.HintAnswer, re)
	}

	labels++
	hint := dnszone.HintAnswer
	encloser = z.Apex()
Search:
	for i, start := dnsutil.Prev(qname, labels); !start; i, start = dnsutil.Prev(qname, labels) {
		node, ok := z.Get(qname[i:])
		if ok {
			encloser = node

			// Check for delegation, thus NS and (later) DELEG records. If this set contain NS records we have a delegation.
			for _, rr := range node.RRs {
				if _, ok := rr.(*dns.NS); ok {
					hint = dnszone.HintDelegation
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
				hint = dnszone.HintWildcard
			}
		}

		labels++
	}

	if hint == dnszone.HintWildcard {
		return dnszone.Synthesize(z, r, sosynthesis, encloser, re)
	}

	return dnszone.MsgFound(z, r, encloser, hint, re)
}
