package ecs

import (
	"context"
	"net"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
)

type Ecs struct{}

func (e *Ecs) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		for _, o := range r.Pseudo {
			if ecs, ok := o.(*dns.SUBNET); ok {
				ctx = dnsctx.WithValue(ctx, dnsctx.Key(e, "address"), net.IP(ecs.Address.AsSlice()))
				break
			}
		}
		next.ServeDNS(ctx, w, r)
	})
}
