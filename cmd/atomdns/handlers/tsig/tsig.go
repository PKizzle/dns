package tsig

import (
	"context"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
)

type Tsig struct {
	TSIG       *dns.TSIG
	TSIGSecret string // base64
}

func (t *Tsig) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		// do the actual check
		dnsctx.WithValue(ctx, dnsctx.Key(t.Key(), dnsctx.Status), true)
		dnsctx.WithValue(ctx, dnsctx.Key(t.Key(), "name"), t.TSIG.Hdr.Name)
		dnsctx.WithValue(ctx, dnsctx.Key(t.Key(), "secret"), t.TSIGSecret)
		dnsctx.WithValue(ctx, dnsctx.Key(t.Key(), "algorithm"), t.TSIG.Algorithm)

		next.ServeDNS(ctx, w, r)
	})
}
