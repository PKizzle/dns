package store

import (
	"time"

	"codeberg.org/miekg/dns"
)

// A node is stored in the store.
type Node struct {
	Name   string
	Rcode  uint16
	Time   time.Time
	Answer []dns.RR
	Ns     []dns.RR
	Extra  []dns.RR
}

// Less compares nodes a, b by Name and returns true if a is less than b.
func Less(a, b Node) bool {
	x := dns.CompareName(a.Name, b.Name)
	return x == -1
}

// Get gets the node under name from the store.
func (s *Store) Get(name string) (Node, bool) {
	n, ok := s.Tree.Get(Node{Name: name})
	if ok {
		return n, true
	}
	return Node{}, false
}

// Set sets the node under name from the store. If successful it return the name, otherwise the empty string.
func (s *Store) Set(m *dns.Msg) string {
	if m.Rcode != dns.RcodeNameError && m.Rcode != dns.RcodeSuccess {
		return ""
	}
	if m.Question[0].Header().Class != dns.ClassINET {
		return ""
	}
	node := Node{
		Name:   m.Question[0].Header().Name,
		Rcode:  m.Rcode,
		Time:   time.Now(),
		Answer: m.Answer,
		Ns:     m.Ns,
		Extra:  m.Extra,
	}

	s.Tree.Set(node)
	return node.Name
}
