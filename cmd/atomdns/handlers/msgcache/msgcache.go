package msgcache

import (
	"context"
	"io"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnslog"
	"codeberg.org/miekg/dns/dnstest"
	"github.com/tidwall/btree"
)

type Msgcache struct {
	Tree *btree.BTreeG[Node]
}

func (m *Msgcache) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		if x := m.Retrieve(r); x != nil {
			x.Data = r.Data
			x = dnsctx.Funcs(ctx, x)
			if err := x.Pack(); err != nil {
				dnslog.PackFail(ctx, log(), Err(err))
			}
			io.Copy(w, x)
			return
		}

		rw := dnstest.NewRecorder(w)

		next.ServeDNS(ctx, rw, r)

		rw.Msg = dnsctx.Funcs(ctx, rw.Msg)
		if err := rw.Msg.Pack(); err != nil {
			dnslog.PackFail(ctx, log(), Err(err))
		}
		io.Copy(w, rw.Msg)

		m.Set(rw.Msg)
	})
}
