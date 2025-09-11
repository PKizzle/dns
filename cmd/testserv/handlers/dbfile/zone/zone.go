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
	"fmt"
	"os"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/tidwall/btree"
)

// Zone holds the main zone and some meta data of the DNS zone we are serving.
// There is no locking, because after creation this structure is basically read-only.
// Tree will be used to write, but that has its own locking.
type Zone struct {
	Origin string
	Labels int
	Path   string
	Tree   *btree.BTreeG[Node]

	Minimal bool // TODO: needed here?

	q Node // resusable q for retrieving the apex, set in New.
}

// A Node is a DNS node in the tree.
type Node struct {
	Name string
	RRs  []dns.RR // all the rrs with owner name 'name'.
}

func less(a, b Node) bool {
	x := dns.CompareName(a.Name, b.Name)
	return x == -1
}

func New(origin, path string) *Zone {
	return &Zone{
		Origin:  dnsutil.Canonical(origin),
		Labels:  dnsutil.Labels(dnsutil.Canonical(origin)),
		Path:    path,
		Tree:    btree.NewBTreeG(less),
		Minimal: true,
		q:       Node{Name: dnsutil.Canonical(origin)},
	}
}

// Load loads a new zone with origin from path from z.
func (z *Zone) Load() error {
	f, err := os.Open(z.Path)
	if err != nil {
		return err
	}
	zp := dns.NewZoneParser(f, z.Origin, z.Path)
	zp.SetIncludeAllowed(true)
	soa := 0
	// TODO(miek): various optimizations: gather names until we have a different one, then insert.
	// Downside: RR's are pointers so we need to empty out the structure and then refill it next time.
	// something Set also does.
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if _, ok := rr.(*dns.SOA); ok {
			soa++
		}

		z.Set([]dns.RR{rr})
	}
	if zp.Err() != nil {
		return fmt.Errorf("failed to parse zone %q with origin %q: %s ", z.Path, z.Origin, zp.Err())
	}
	if soa != 1 {
		return fmt.Errorf("zone %q with origin %q has no SOA or not a single SOA records", z.Path, z.Origin)
	}
	return nil
}

func (z *Zone) Apex() []dns.RR {
	found, _ := z.Tree.Get(z.q)
	return found.RRs
}

// Set sets the RRs in the zone. It needs to create any empty non-terminals it has. Meaning for each label
// a lookup is done if there already is an empty non-terminal, if not an empty set is inserted.
// We should never be called to insert ENT (or names without RRs attached to them.
func (z *Zone) Set(rrs []dns.RR) string {
	// If the name already exist, we can just add our stuff to the node and we are done.
	node := Node{Name: rrs[0].Header().Name}
	n, ok := z.Tree.Get(node)
	if ok {
		n.RRs = append(n.RRs, rrs...)
		z.Tree.Set(n)
		return rrs[0].Header().Name
	}
	// The name didn't exist before, we need to insert it.
	node.RRs = rrs
	z.Tree.Set(node)
	// Now we need to create (potential) ENT up to the apex. So when just insert www.a.b.example.org. we need
	// make a.b.example.org, b.example.org. So we need N+2 labels, if this zone has N labels. If we only have
	// 1 label more, we just created the correct node.
	labels := dnsutil.Labels(node.Name)
	if labels == z.Labels+1 {
		return rrs[0].Header().Name
	}

	// Else we create (or check if they exist) the intermediate nodes.
	off := 0
	name := rrs[0].Header().Name
	for i := 1; i < labels-z.Labels; i++ {
		off, _ = dnsutil.Next(name, off)

		node := Node{Name: name[off:]}
		if _, ok := z.Tree.Get(node); ok {
			continue // already exist, nothing to add
		}
		z.Tree.Set(node) // set an empty node
	}
	return rrs[0].Header().Name
}

// Get gets the RRs under name from z.
func (z *Zone) Get(name string) ([]dns.RR, bool) {
	node := Node{Name: name}
	n, ok := z.Tree.Get(node)
	if ok {
		return n.RRs, true
	}
	return nil, false
}

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
	found := []dns.RR{}
	wildcard := []dns.RR{}

	// We have 2 loops, the Search loop and then a "found" loop. The search loop lookups up the correct
	// record set from the zone. The second loop (in z.Msg) then creates a message with the correct RRs in the sections.
	// This might involve even more zone lookups for cname and glue records. The returned message can be written to the client.
	qname := r.Question[0].Header().Name

	// Doing apex queries separate simplifies the loop below as we can not have delegation, wildcards, etc.
	if z.Labels == dnsutil.Labels(qname) {
		return z.Msg(r, z.Apex(), hintAnswer, "" /* closest can remain empty */)
	}

	labels++
	hint := hintAnswer
	closest := z.Origin // closest contains the last matching name, this is closet encloser, we start with the zone's origin
	wildcardclosest := ""
Search:
	for i, start := dnsutil.Prev(qname, labels); !start; i, start = dnsutil.Prev(qname, labels) {
		set, ok := z.Get(qname[i:])
		if ok {
			found = set
			closest = qname[i:]

			// Check for delegation, thus NS and (later?) DELEG records. If this set contain NS records we
			// have a delegation.
			for _, rr := range found {
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
			j, _ := dnsutil.Next(qname, 0)
			set, ok := z.Get("*." + qname[j:])
			if ok {
				wildcard = set
				wildcardclosest = qname[j:]
				hint = hintWildcard
			}
		}

		labels++
	}
	wildcard = wildcard
	wildcardclosest = wildcardclosest

	return z.Msg(r, found, hint, closest)
}

func (z *Zone) Msg(r *dns.Msg, found []dns.RR, hint Hint, closest string) *dns.Msg {
	// Copy because there RRs _will_ be modified at some point, even here for dname and cname post processing.
	section := &r.Answer
	qtype := dns.RRToType(r.Question[0])
	if hint == hintDelegation {
		section = &r.Ns
		qtype = dns.TypeNS
	}

	// NXDOOMAIN response.
	if len(found) == 0 {
		// if hint is !wildcard (because otherwise hit)
		for _, rr := range z.Apex() {
			if _, ok := rr.(*dns.SOA); ok {
				r.Ns = append(r.Ns, rr.Copy())
			}
		}
		r.Rcode = dns.RcodeNameError
		return r
	}

	for _, rr := range found {
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
		for _, rr := range found {
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

	// NODATA response.
	if len(*section) == 0 {
		for _, rr := range z.Apex() {
			if _, ok := rr.(*dns.SOA); ok {
				r.Ns = append(r.Ns, rr.Copy())
			}
			if r.Security {
				if _, ok := rr.(*dns.NSEC); ok {
					r.Ns = append(r.Ns, rr.Copy())
				}
			}
			if r.Security {
				if s, ok := rr.(*dns.RRSIG); ok {
					if s.TypeCovered == dns.TypeSOA || s.TypeCovered == dns.TypeNSEC {
						r.Ns = append(r.Ns, rr.Copy())
					}
				}
			}
		}
	}

	return r
}
