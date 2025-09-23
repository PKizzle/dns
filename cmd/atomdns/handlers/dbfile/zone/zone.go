// Package implement a DNS zone, held in a binary tree. Each RR(set) that gets inserted will need to create
// any empty non-terminals (ENT) it possesses. I.e. inserting www.example.org into example.org is easy, but when
// www.a.b.c.example.org inserts we need to make sure that 'c.example.org', 'b.c.example.org' and
// 'a.b.c.example.org' also exist and are ENTs (have no actual RRs). For deleted the opposite must happen. As
// an example from RFC 4592, the record:  sub.*.example.  TXT  "this is not a wildcard" is a fun one. As this
// means the '*.example' ENT exists meaning that bogus.example. gets a NODATA response instead of NXDOMAIN.
//
// Doing this on insert sucks a bit, but makes the lookup code much more simple (and correct), which is more
// important for a DNS server.
//
// CNAME, DNSSEC, wildcards, etc. are all supported. Not supported is: DNAME (RFC 6672), the server will just
// return the DNAME without any of the (in the RFC required) post-processing.
package zone

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

	apex Node // apex node, filled after a Load.
}

// A Node is a DNS node in the tree.
type Node struct {
	Name string
	RRs  []dns.RR // all the rrs with owner name 'name'.
}

// Restart is used in the (recursive) calling of Retrieve to complete a CNAME chain. The i index is used to avoid loops
// in the recursion and we break at 8.
type Restart struct {
	Answer []dns.RR // current set of RRs that need to go in the final response
	I      int      // break recursion at I > 7
}

func (n Node) String() string {
	sb := strings.Builder{}
	for i := range n.RRs {
		sb.WriteString(n.RRs[i].String())
		sb.WriteByte('\n')
	}
	return sb.String()
}

func less(a, b Node) bool {
	x := dns.CompareName(a.Name, b.Name)
	return x == -1
}

func New(origin, path string) *Zone {
	z := &Zone{
		Origin: dnsutil.Canonical(origin),
		Labels: dnsutil.Labels(dnsutil.Canonical(origin)),
		Path:   func() string { a, _ := filepath.Abs(path); return a }(),
		Tree:   btree.NewBTreeG(less),
	}
	return z
}

// Load loads a new zone with origin from path from z. Load also sets the apex, so the z.Apex can return that.
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
		node := Node{Name: rr.Header().Name, RRs: []dns.RR{rr}}
		z.Set(node)
	}
	if zp.Err() != nil {
		return fmt.Errorf("failed to parse zone %q with origin %q: %s ", z.Path, z.Origin, zp.Err())
	}
	if soa != 1 {
		return fmt.Errorf("zone %q with origin %q has no SOA or not a single SOA records", z.Path, z.Origin)
	}
	z.apex, _ = z.Tree.Get(Node{Name: z.Origin})
	return nil
}

func (z *Zone) Apex() Node { return z.apex }

// Set sets the RRs in the zone. It needs to create any empty non-terminals it has. Meaning for each label
// a lookup is done if there already is an empty non-terminal, if not an empty set is inserted.
// We should never be called to insert ENT (or names without RRs attached to them.
func (z *Zone) Set(node Node) string {
	// If the name already exist, we can just add our stuff to the node and we are done.
	n, ok := z.Tree.Get(node)
	if ok {
		n.RRs = append(n.RRs, node.RRs...)
		z.Tree.Set(n)
		return node.Name
	}
	// The name didn't exist before, we need to insert it.
	z.Tree.Set(node)
	// Now we need to create (potential) ENT up to the apex. So when just insert www.a.b.example.org. We need
	// make a.b.example.org, b.example.org. So we need N+2 labels, if this zone has N labels. If we only have
	// 1 label more, we just created the correct node.
	labels := dnsutil.Labels(node.Name)
	if labels == z.Labels+1 {
		return node.Name
	}

	// Else we create (or check if they exist) the intermediate nodes.
	off := 0
	name := node.Name
	for i := 1; i < labels-z.Labels; i++ {
		off, _ = dnsutil.Next(name, off)

		node := Node{Name: name[off:]}
		if _, ok := z.Tree.Get(node); ok {
			continue // already exist, nothing to add
		}
		z.Tree.Set(node) // set an empty node
	}
	return node.Name
}

// Get gets the node under name from z.
func (z *Zone) Get(name string) (Node, bool) {
	n, ok := z.Tree.Get(Node{Name: name})
	if ok {
		return n, true
	}
	return Node{}, false
}

// Previous returns the logical previous name from name.
func (z *Zone) Previous(name string) Node {
	node := Node{}
	z.Tree.Descend(Node{Name: name}, func(n Node) bool {
		node = n
		return false
	})
	return node
}
