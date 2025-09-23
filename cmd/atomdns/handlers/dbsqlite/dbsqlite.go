package dbsqlite

import (
	"context"
	"io"

	"codeberg.org/miekg/dns"
	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

type Dbsqlite struct {
	Path string

	db    *sqlx.DB
	Zones map[string]*Zone // read-only after startup
}

func (d *Dbsqlite) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		z := d.Zones[dns.Zone(ctx)]

		m := z.Retrieve(r, nil)
		m.Data = r.Data
		m.Pack()

		io.Copy(w, m)
	})
}
