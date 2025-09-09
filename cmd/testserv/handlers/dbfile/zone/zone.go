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

type Hint int

const (
	answer Hint = iota
	delegetion
	cname
	dname
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
	hint := answer

	// Doing apex queries seperate simplifies the loop below, so it makes sense to do so.

Search:
	for idx, start := dnsutil.Prev(qname, labels); !start; idx, start = dnsutil.Prev(qname, labels) {
		q.Header().Name = qname[idx:]
		set, ok := z.Tree.Get([]dns.RR{q})
		if ok {
			// Check for delegation, thus NS and (later?) DELEG records. If this set contain NS records we put those
			// in the authority section + look for glue if in baliwick.
			found = set

			for _, rr := range found {
				if _, ok := rr.(*dns.NS); ok {
					// we loop through 'found' again, so we can just break
					break Search
				}
			}
		} else {
			// check for wildcard of the correct type
		}

		labels++
	}

	return z.Msg(r, found, hint)
}

func (z *Zone) Msg(r *dns.Msg, found []dns.RR, hint Hint) *dns.Msg {
	// Copy because there RRs _will_ be modified at some point.

	qtype := dns.RRToType(r.Question[0])
	if len(found) > 0 {
		for _, rr := range found {
			if dns.RRToType(rr) == qtype {
				r.Answer = append(r.Answer, rr.Copy())
			}
		}
		if r.Security {
			for _, rr := range found {
				if s, ok := rr.(*dns.RRSIG); ok {
					if s.TypeCovered == qtype {
						r.Answer = append(r.Answer, rr.Copy())
					}
				}
			}
		}
		return r
	}
	return nil
}
