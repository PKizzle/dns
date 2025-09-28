package store

import (
	"context"
	"io"
	"sync"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsmsg"
	"codeberg.org/miekg/dns/dnstest"
	"github.com/tidwall/btree"
)

type Store struct {
	// Max contains the longest existing name we seem for a suffix. Searches are capped at this limit.
	sync.RWMutex // protects Max
	// Tree contains the cached nodes.
	Tree *btree.BTreeG[Node]
}

func (s *Store) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := s.Retrieve(r)
		if m != nil {
			m.Data = r.Data
			m = dnsmsg.Funcs(ctx, m)
			if err := m.Pack(); err != nil {
				log.Debug("Pack failure", Err(err))
			}
			io.Copy(w, m)
			return
		}

		rw := dnstest.NewRecorder(w)

		next.ServeDNS(ctx, rw, r)

		m = rw.Msg
		m = dnsmsg.Funcs(ctx, m)
		if err := m.Pack(); err != nil {
			log.Debug("Pack failure", Err(err))
		}
		io.Copy(w, m)
	})
}
