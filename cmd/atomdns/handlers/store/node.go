package store

import (
	"time"

	"codeberg.org/miekg/dns"
)

// A node is stored in the store.
type Node struct {
	Name     string
	Rcode    uint16
	Time     time.Time
	Question dns.RR
	Msg      *dns.Msg
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

// Set sets the node under name from the store.
func (s *Store) Set(node Node) string {
	s.Tree.Set(node)
	return node.Name
}
