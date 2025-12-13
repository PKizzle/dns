package dnszone

import (
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

// Restart is used in the (recursive) calling of Retrieve to complete a CNAME chain. The i index is used to avoid loops
// in the recursion and we break at 8.
type Restart struct {
	Name   string   // original qname that started this sequence
	Answer []dns.RR // current set of RRs that need to go in the final response
	I      int      // break recursion at I > 7
}

// A Node is a DNS node in the tree. The class is not stored an defaults to IN.
type Node struct {
	Name   string
	TTL    uint32
	Type   uint16
	RDATAs []dns.RDATA
}

// RRs returns the full RRs from a node.
func (n *Node) RRs() []dns.RR {
	rrs := make([]dns.RR, len(n.RDATAs))
	for i := range n.RDATAs {
		if newFn, ok := dns.TypeToRR[n.Type]; ok {
			rrs[i] = newFn()
			rdataFn := dns.TypeToRDATA[n.Type]
			rdataFn(rrs[i], n.RDATAs[i])
		} else {
			rrs[i] = &dns.RFC3597{RFC3597: n.RDATAs[i].(rdata.RFC3597)}
		}
		rrs[i].Header().Class = dns.ClassINET
		rrs[i].Header().Name = n.Name
		rrs[i].Header().TTL = n.TTL
	}

	return rrs
}

// String output the string representation for a Node. Mostly used for debugging.
func (n *Node) String() string {
	sb := strings.Builder{}
	for _, rr := range n.RRs() {
		sb.WriteString(rr.String())
		sb.WriteByte('\n')
	}
	return sb.String()
}

// Less compares nodes a, b by Name and returns true if a is less than b.
func Less(a, b *Node) bool { return dns.CompareName(a.Name, b.Name) == -1 }
