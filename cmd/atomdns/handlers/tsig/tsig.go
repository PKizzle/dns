package tsig

import (
	"context"

	"codeberg.org/miekg/dns"
)

type Tsig struct {
	TSIG       *dns.TSIG
	TSIGSecret string // base64
}

func (t *Tsig) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	})
}
