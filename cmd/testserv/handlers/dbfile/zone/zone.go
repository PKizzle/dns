package zone

import (
	"fmt"
	"os"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/tidwall/btree"
)

// Interface defines the methods for each db* implementation. This is currently unused, and if used
// this needs to live in the pkg/db or something, not tucked away here.
//
// This is the interface dbfile implements on top of the b-tree.
type Interface interface {
	New(origin, path string) Interface
	Load(origin, path string) Interface
	Set([]dns.RR) ([]dns.RR, bool)
	Get([]dns.RR) ([]dns.RR, bool)
	Walk(func([]dns.RR) bool)
	AuthoritativeWalk(func([]dns.RR, bool) bool)
}

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
	println("COMP", a[0].Header().Name, b[0].Header().Name)
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

// Get looks up the qname and qtype in the Zone z. It returns a message with the RRs (if found) in the
// correct places. In case of NXDOMAIN or NODATA respones the message will also contain the correct
// information.
func (z *Zone) Get(m *dns.Msg) *dns.Msg {
	// If here, we are guaranteed that this zone has the correct origin and the qname falls in this zone.
	// so we should be able to Prev to the first label that should fall in this zone.
	r := new(dns.Msg)
	dnsutil.SetReply(r, m)

	qname, qtype := dnsutil.Question(r)

	labels := z.Labels
	found := []dns.RR{}

	q := r.Question[0]
	for idx, start := dnsutil.Prev(qname, labels); !start; idx, start = dnsutil.Prev(qname, labels) {
		q.Header().Name = qname[idx:]
		set, ok := z.Tree.Get([]dns.RR{q})
		if ok {
			found = set
		} else {
			// check for wildcard of the correct type
		}
		// If delegated, returns the delegation, wildcard, DELEG. a lot of complexity will be in this function.
		labels++
	}
	if len(found) > 0 {
		// here we need to copy these out of the zone because they are going to be written to, TTL, among other things
		for _, rr := range found {
			if dns.RRToType(rr) == qtype {
				r.Answer = append(r.Answer, rr.Copy())
			}
			// if dnssec
		}
		return r
	}
	return nil
}
