package nsid

import (
	"context"
	"encoding/hex"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/testserv/internal/dnsmsg"
)

type Nsid struct {
	Data string
}

func (n *Nsid) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		for _, o := range r.Pseudo {
			if _, ok := o.(*dns.NSID); ok {
				ctx = dnsmsg.WithValue(ctx, n.Key(),
					func(m *dns.Msg) *dns.Msg {
						nsid := &dns.NSID{Nsid: hex.EncodeToString([]byte(n.Data))}
						m.Pseudo = append(m.Pseudo, nsid)
						return m
					})
				break
			}
		}

		next.ServeDNS(ctx, w, r)
	})
}
