package zone

import (
	"fmt"
	"os"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/tidwall/btree"
)

// Zone holds the main zone and some meta data of the DNS zone we are serving.
type Zone struct {
	Origin string
	Path   string
	Tree   *btree.BTreeG[[]dns.RR]
}

func less(a, b []dns.RR) bool {
	x := dns.CompareName(a[0].Header().Name, b[0].Header().Name)
	return x == -1
}

func New(origin, path string) *Zone {
	return &Zone{Origin: origin, Path: path, Tree: btree.NewBTreeG(less)}
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
