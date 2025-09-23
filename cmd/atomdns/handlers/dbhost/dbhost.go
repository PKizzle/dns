package dbhost

import (
	"context"

	"codeberg.org/miekg/dns"
)

type Dbhost struct {
	Path string
}

func (d *Dbhost) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		//...
	})
}
