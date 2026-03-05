package unpack

import (
	"context"
	"fmt"

	"codeberg.org/miekg/dns"
)

type Unpack int

func (u *Unpack) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		if err := r.Unpack(); err != nil {
			log().Debug("Unpack failure", Err(err), "zone", dns.Zone(ctx))
			return
		}
		if len(r.Question) > 0 {
			cl := r.Question[0].Header().Class
			if cl != dns.ClassINET && cl != dns.ClassCHAOS {
				log().Debug("Forbidden class", Err(fmt.Errorf("class is not IN or CH")), "zone", dns.Zone(ctx))
				return
			}
		}

		next.ServeDNS(ctx, w, r)
	})
}
