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
	Origin  string
	Labels  int
	Path    string
	Minimal bool
	Tree    *btree.BTreeG[[]dns.RR]

	q []dns.RR // resusable q for retrieving the apex, set in New.
}

func less(a, b []dns.RR) bool {
	x := dns.CompareName(a[0].Header().Name, b[0].Header().Name)
	return x == -1
}

func New(origin, path string) *Zone {
	return &Zone{
		Origin:  dnsutil.Canonical(origin),
		Labels:  dnsutil.Labels(dnsutil.Canonical(origin)),
		Path:    path,
		Tree:    btree.NewBTreeG(less),
		Minimal: true,
		q:       []dns.RR{&dns.SOA{Hdr: dns.Header{Name: dnsutil.Canonical(origin)}}},
	}
}

// Load loads a new zone with origin from path.
func Load(origin, path string) (*Zone, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	zp := dns.NewZoneParser(f, dnsutil.Canonical(origin), path)
	zp.SetIncludeAllowed(true)
	z := New(origin, path)
	soa := 0
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if _, ok := rr.(*dns.SOA); ok {
			soa++
		}

		set, ok := z.Tree.Get([]dns.RR{rr})
		if ok {
			set = append(set, rr)
			z.Tree.Set(set)
			continue
		}

		z.Tree.Set([]dns.RR{rr})
	}
	if zp.Err() != nil {
		return nil, fmt.Errorf("failed to parse zone %q with origin %q: %s ", path, origin, zp.Err())
	}
	if soa != 1 {
		return nil, fmt.Errorf("zone %q with origin %q has no SOA or not a single SOA records", path, origin)
	}
	return z, nil
}

func (z *Zone) Apex() []dns.RR {
	found, _ := z.Tree.Get(z.q)
	return found
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

// Get looks up the qname and qtype in the Zone z. It returns a message with the RRs (if found) in the
// correct places. In case of NXDOMAIN or NODATA respones the message will also contain the correct
// information.
func (z *Zone) Get(m *dns.Msg) *dns.Msg {
	// If here, we are guaranteed that this zone has the correct origin and the qname falls in this zone.
	// so we should be able to Prev to the first label that should fall in this zone.
	r := new(dns.Msg)
	dnsutil.SetReply(r, m)

	labels := z.Labels
	found := []dns.RR{}

	// We have 2 loops, the Search loop and then a "found" loop. The search loop lookups up the correct
	// record set from the zone. The second loop (in z.Msg) then creates a message with the correct RRs in the sections.
	// This might involve even more zone lookups for cname and glue records. The returned message can be written to the client.
	q := r.Question[0]
	qname := q.Header().Name

	// Doing apex queries seperate simplifies the loop below as we can not have delegation, wildcards, etc.
	if z.Labels == dnsutil.Labels(qname) {
		return z.Msg(r, z.Apex(), hintAnswer)
	}

	labels++
	hint := hintAnswer
Search:
	for i, start := dnsutil.Prev(qname, labels); !start; i, start = dnsutil.Prev(qname, labels) {
		q.Header().Name = qname[i:]
		set, ok := z.Tree.Get([]dns.RR{q})
		if ok {
			found = set

			// Check for delegation, thus NS and (later?) DELEG records. If this set contain NS records we
			// have a delegation.
			for _, rr := range found {
				if _, ok := rr.(*dns.NS); ok {
					hint = hintDelegation
					break Search
				}
			}

		} else {

			// Skip a label to the right again and replace with '*', this should work by definition. If we
			// find a wildcard label here the search ends too; wildcard found, obscures everything below.
			j, _ := dnsutil.Next(qname, 0)
			q.Header().Name = "*." + qname[j:]
			set, ok := z.Tree.Get([]dns.RR{q})
			if ok {
				found = set
				hint = hintWildcard
				break Search
			}

			q.Header().Name = qname[i:] // reset name
		}

		labels++
	}

	return z.Msg(r, found, hint)
}

// glue, soa apex
// cname, dname

func (z *Zone) Msg(r *dns.Msg, found []dns.RR, hint Hint) *dns.Msg {
	// Copy because there RRs _will_ be modified at some point, even here for dname and cname post processing.
	section := &r.Answer
	qtype := dns.RRToType(r.Question[0])
	if hint == hintDelegation {
		section = &r.Ns
		qtype = dns.TypeNS
	}

	if len(found) > 0 {
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
		return r
	}
	return nil
}
