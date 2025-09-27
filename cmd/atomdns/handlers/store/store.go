package store

import (
	"context"
	"io"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsmsg"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
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
		rw := dnstest.NewRecorder(w)
		next.ServeDNS(ctx, rw, r)

		RequestDuration.WithLabelValues(dns.Zone(ctx), net, fam).Observe(time.Since(rw.Start).Seconds())
		ResponseSize.WithLabelValues(dns.Zone(ctx), net, fam).Observe(float64(len(rw.Msg.Data)))
		Responses.WithLabelValues(dns.Zone(ctx), net, fam, dnsutil.RcodeToString(rw.Msg.Rcode)).Inc()

		io.Copy(w, rw.Msg)

		m = dnsmsg.Funcs(ctx, m)
		if err := m.Pack(); err != nil {
			log.Debug("Pack failure", Err(err))
		}
		io.Copy(w, m)
	})
}
