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
	"codeberg.org/miekg/dns/dnsutil"
)

// Hints give a hint to z.Msg on what type of answer we got. This could be (mostly?) be done in Msg, but
// requires redoing work already done, easier to just notify what we have.
type Hint int

const (
	hintAnswer Hint = iota
	hintDelegation
	hintCname
	hintDname
	hintWildcard
)

// Retrieve looks up the qname and qtype in the Zone z. It returns a message with the RRs (if found) in the
// correct places. In case of NXDOMAIN or NODATA response the message will also contain the correct
// information.
func (z *Zone) Retrieve(m *dns.Msg) *dns.Msg {
	// If here, we are guaranteed that this zone has the correct origin and the qname falls in this zone.
	// so we should be able to Prev to the first label that should fall in this zone.
	r := new(dns.Msg)
	dnsutil.SetReply(r, m)

	labels := z.Labels
	sosynthesis, encloser := Node{}, Node{} // source of synthesis and closes encloser RRset + names.

	// We have 2 loops, the Search loop and then a "found" loop. The search loop lookups up the correct
	// record set from the zone. The second loop (in z.Msg) then creates a message with the correct RRs in the sections.
	// This might involve even more zone lookups for cname and glue records. The returned message can be written to the client.
	qname := r.Question[0].Header().Name

	// Doing apex queries separate simplifies the loop below as we can not have delegation, wildcards, etc.
	if z.Labels == dnsutil.Labels(qname) {
		return z.MsgFound(r, z.Apex(), hintAnswer)
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

			// TODO: cname, dname

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
		return z.MsgSynthesize(r, sosynthesis, encloser)
	}

	return z.MsgFound(r, encloser, hint)
}

// MsgWildcard handles all wildcard responses, we are only called when we hit a wildcard and didn't find any
// more specific. I.e. original qname did not exist. Now we need to assemble the answer plus adding the NSECs
// that validte the answer. If sosynthesis.Name != encloser.Name, those two NSECs need to be added.
func (z *Zone) MsgSynthesize(r *dns.Msg, sosynthesis, encloser Node) *dns.Msg {
	// Synthesis, can still lead to no data if the qtype doesn't match.
	if len(sosynthesis.RRs) > 0 {
		qtype := dns.RRToType(r.Question[0])
		for _, rr := range sosynthesis.RRs {
			if dns.RRToType(rr) == qtype {
				rr1 := rr.Copy()
				rr1.Header().Name = r.Question[0].Header().Name // replace owner names with the qname
				r.Answer = append(r.Answer, rr1)
			}
			if r.Security {
				if _, ok := rr.(*dns.NSEC); ok {
					r.Ns = append(r.Ns, rr.Copy()) // SoS' NSEC
				}
				if s, ok := rr.(*dns.RRSIG); ok {
					if s.TypeCovered == qtype {
						rr1 := rr.Copy()
						rr1.Header().Name = r.Question[0].Header().Name
						r.Answer = append(r.Answer, rr1)
					}
					if s.TypeCovered == dns.TypeNSEC {
						r.Ns = append(r.Ns, rr.Copy())
					}
				}

			}
		}
		if len(r.Answer) > 0 {
			return r
		}
		// nodata, as the type isn't there, only need SOA + RRSIG, lets prepend so it comes first
		for _, rr := range z.Apex().RRs {
			if _, ok := rr.(*dns.SOA); ok {
				r.Ns = append(r.Ns, rr.Copy())
			}
			if r.Security {
				if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == dns.TypeSOA {
					r.Ns = append(r.Ns, rr.Copy())
				}
			}
		}
		return r
	}

	// NODATA response, when there are no RRs or when we fall through from above.
	if len(sosynthesis.RRs) == 0 {
		for _, rr := range z.Apex().RRs {
			if _, ok := rr.(*dns.SOA); ok {
				r.Ns = append(r.Ns, rr.Copy())
			}
			if r.Security {
				if _, ok := rr.(*dns.NSEC); ok {
					r.Ns = append(r.Ns, rr.Copy())
				}
				if s, ok := rr.(*dns.RRSIG); ok && (s.TypeCovered == dns.TypeSOA || s.TypeCovered == dns.TypeNSEC) {
					r.Ns = append(r.Ns, rr.Copy())
				}
			}
		}
		if r.Security { // proving there is no wildcard
			if prev, ok := z.Previous(r.Question[0].Header().Name); ok {
				// we already have the SOA records, don't repeat.
				if !dns.EqualName(prev.Name, z.Origin) {
					for _, rr := range prev.RRs {
						if _, ok := rr.(*dns.NSEC); ok {
							r.Ns = append(r.Ns, rr.Copy())
						}
						if s, ok := rr.(*dns.RRSIG); ok && (s.TypeCovered == dns.TypeSOA || s.TypeCovered == dns.TypeNSEC) {
							r.Ns = append(r.Ns, rr.Copy())
						}
					}
				}
			}
		}
		return r
	}

	return r
}

func (z *Zone) MsgFound(r *dns.Msg, encloser Node, hint Hint) *dns.Msg {
	// Copy because there RRs _will_ be modified at some point, even here for dname and cname post processing.
	section := &r.Answer
	qtype := dns.RRToType(r.Question[0])
	if hint == hintDelegation {
		section = &r.Ns
		qtype = dns.TypeNS
	}

	// NXDOOMAIN response.
	// prev needed?
	if encloser.Name == "" { // found.RRs must be empty as well
		for _, rr := range z.Apex().RRs {
			if _, ok := rr.(*dns.SOA); ok {
				r.Ns = append(r.Ns, rr.Copy())
			}
		}
		r.Rcode = dns.RcodeNameError
		return r
	}

	for _, rr := range encloser.RRs {
		if dns.RRToType(rr) == qtype {
			*section = append(*section, rr.Copy())
		}
		switch {
		case hint == hintDelegation && r.Security:
			if _, ok := rr.(*dns.DS); ok {
				*section = append(*section, rr.Copy())
			}
		}
	}
	if r.Security {
		for _, rr := range encloser.RRs {
			if s, ok := rr.(*dns.RRSIG); ok {
				if s.TypeCovered == qtype {
					*section = append(*section, rr.Copy())
				}
				if hint == hintDelegation {
					if s.TypeCovered == dns.TypeDS {
						*section = append(*section, rr.Copy())
					}
				}
			}
		}
	}

	if len(*section) > 0 {
		return r
	}

	// NODATA response.
	for _, rr := range z.Apex().RRs {
		if _, ok := rr.(*dns.SOA); ok {
			r.Ns = append(r.Ns, rr.Copy())
		}
		if r.Security {
			if _, ok := rr.(*dns.NSEC); ok {
				r.Ns = append(r.Ns, rr.Copy())
			}
			if s, ok := rr.(*dns.RRSIG); ok && (s.TypeCovered == dns.TypeSOA || s.TypeCovered == dns.TypeNSEC) {
				r.Ns = append(r.Ns, rr.Copy())
			}
		}
	}

	return r
}
