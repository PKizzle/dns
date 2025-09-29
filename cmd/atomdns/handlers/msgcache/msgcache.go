package msgcache

import (
	"context"
	"io"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsmsg"
	"codeberg.org/miekg/dns/dnstest"
	"github.com/tidwall/btree"
)

type Msgcache struct {
	Tree *btree.BTreeG[Node]
}

func (m *Msgcache) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		if x := m.Retrieve(r); m != nil {
			x.Data = r.Data
			x = dnsmsg.Funcs(ctx, x)
			if err := x.Pack(); err != nil {
				log.Debug("Pack failure", Err(err))
			}
			io.Copy(w, x)
			return
		}

		rw := dnstest.NewRecorder(w)

		next.ServeDNS(ctx, rw, r)

		x := rw.Msg
		x = dnsmsg.Funcs(ctx, x)
		if err := x.Pack(); err != nil {
			log.Debug("Pack failure", Err(err))
		}
		io.Copy(w, x)

		m.Set(x)
	})
}
