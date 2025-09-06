package global

import (
	"context"

	"codeberg.org/miekg/dns"
)

type Global struct {
	Root       string
	Prometheus string
}

func (g *Global) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {})
}
