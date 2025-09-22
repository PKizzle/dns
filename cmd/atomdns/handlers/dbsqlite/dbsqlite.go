package dbsqlite

import (
	"context"

	"codeberg.org/miekg/dns"
	_ "modernc.org/sqlite"
)

type Dbsqlite struct {
	*Zone
}

func (d *Dbsqlite) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {

	})
}
