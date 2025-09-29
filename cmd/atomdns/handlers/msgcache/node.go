package msgcache

import (
	"math/rand/v2"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
)

// A node is stored in the store.
type Node struct {
	Name   string
	Type   uint16
	Rcode  uint16
	Time   time.Time
	Answer []dns.RR
	Ns     []dns.RR
	Extra  []dns.RR
}

// Less compares nodes a, b by Name and returns true if a is less than b.
func Less(a, b Node) bool {
	x := dns.CompareName(a.Name, b.Name)
	if x != 0 {
		return x == -1
	}
	return a.Type < b.Type
}

// Get gets the node under name from the store.
func (m *Msgcache) Get(name string) (Node, bool) {
	n, ok := m.Tree.Get(Node{Name: name})
	if ok {
		return n, true
	}
	return Node{}, false
}

// Set sets the node under name from the store. If successful it return the name, otherwise the empty string.
func (m *Msgcache) Set(x *dns.Msg) string {
	if x.Rcode != dns.RcodeNameError && x.Rcode != dns.RcodeSuccess {
		return ""
	}
	if x.Question[0].Header().Class != dns.ClassINET {
		return ""
	}
	minttl := uint32(600)
	for rr := range x.All() {
		if rr.Header().TTL > minttl {
			minttl = rr.Header().TTL
		}
	}

	if minttl > 604800 /* week */ {
		minttl = 604800
	}

	node := Node{
		Name:   x.Question[0].Header().Name,
		Type:   dns.RRToType(x.Question[0]),
		Rcode:  x.Rcode,
		Time:   time.Now().Add((time.Duration(int(minttl)+rand.IntN(7200)) * time.Second)),
		Answer: x.Answer,
		Ns:     x.Ns,
		Extra:  x.Extra,
	}

	m.Tree.Set(node)
	return node.Name
}

// Delete removes a node from the store.
func (m *Msgcache) Delete(name string) bool {
	_, ok := m.Tree.Delete(Node{Name: name})
	return ok
}

func (n Node) String() string {
	// TODO(miek): builderPool for all of these?
	sb := strings.Builder{}
	sb.WriteString(n.Name)
	sb.WriteByte(' ')
	sb.WriteString(dns.RcodeToString[n.Rcode])
	sb.WriteByte(' ')
	sb.WriteString(n.Time.String())
	for i := range n.Answer {
		sb.WriteString(n.Answer[i].String())
		sb.WriteByte('\n')
	}
	for i := range n.Ns {
		sb.WriteString(n.Answer[i].String())
		sb.WriteByte('\n')
	}
	for i := range n.Extra {
		sb.WriteString(n.Answer[i].String())
		sb.WriteByte('\n')
	}
	return sb.String()
}
