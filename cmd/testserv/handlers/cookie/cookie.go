package cookie

import (
	"context"
	"encoding/hex"
	"hash/fnv"
	"io"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/testserv/internal/dnsmsg"
	"codeberg.org/miekg/dns/dnsutil"
)

type Cookie struct {
	Secret string
}

func (c *Cookie) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		for _, o := range r.Pseudo {
			if cc, ok := o.(*dns.COOKIE); ok {
				if len(cc.Cookie) < 16 {
					// return formerr
					break
				}

				// assume welformed
				h := fnv.New64()
				io.WriteString(h, dnsutil.RemoteIP(w))
				io.WriteString(h, cc.Cookie[:16])
				io.WriteString(h, c.Secret)

				ctx = dnsmsg.WithValue(ctx, c.Key(),
					func(m *dns.Msg) *dns.Msg {
						cookie := &dns.COOKIE{Cookie: hex.EncodeToString(h.Sum(nil))}
						m.Pseudo = append(m.Pseudo, cookie)
						return m
					})
				break
			}
		}

		next.ServeDNS(ctx, w, r)
	})
}
