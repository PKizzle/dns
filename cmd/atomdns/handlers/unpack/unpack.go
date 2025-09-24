package unpack

import (
	"context"
	"log/slog"

	"codeberg.org/miekg/dns"
)

type Unpack int

func (u *Unpack) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		if err := r.Unpack(); err != nil {
			log.Debug("Pack failure", slog.Any("error", err))
		}
		next.ServeDNS(ctx, w, r)
	})
}
