package store

import (
	"context"
	"io"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsmsg"
	"codeberg.org/miekg/dns/dnstest"
	"github.com/tidwall/btree"
)

type Store struct {
	Tree *btree.BTreeG[Node]
}

func (s *Store) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		if m := s.Retrieve(r); m != nil {
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

		m := rw.Msg
		m = dnsmsg.Funcs(ctx, m)
		if err := m.Pack(); err != nil {
			log.Debug("Pack failure", Err(err))
		}
		io.Copy(w, m)

		s.Set(m)
	})
}
