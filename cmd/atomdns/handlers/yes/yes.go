package yes

import (
	"context"

	"codeberg.org/miekg/dns"
)

type Yes struct {
	Caa []string
}

func (y *Yes) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) { next.ServeDNS(ctx, w, r) })
}
