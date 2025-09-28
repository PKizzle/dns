package store

import (
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"github.com/tidwall/btree"
)

func (s *Store) Setup(co *dnsserver.Controller) error {
	for co.Next() {
	}
	s.Tree = btree.NewBTreeG(Less)
	return nil
}
