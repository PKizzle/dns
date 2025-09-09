package dbfile

import (
	"context"
	"time"

	"codeberg.org/miekg/dns"
)

type Dbfile struct {
	Path           string
	Reload         time.Duration
	DisableMinimal bool
}

func (d *Dbfile) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		// do the lookup
	})
}
