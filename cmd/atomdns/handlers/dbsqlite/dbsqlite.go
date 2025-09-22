package dbsqlite

import (
	"context"
	"io"
	"sync"

	"codeberg.org/miekg/dns"
	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

type Dbsqlite struct {
	Path string

	db *sqlx.DB
	// Zones holds all the zone this instance of Dbsqlite is called for.
	Zones        map[string]*Zone
	sync.RWMutex // protects Zones
}

func (d *Dbsqlite) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		d.RLock()
		z := d.Zones[dns.Zone(ctx)]
		d.RUnlock()

		m := z.Retrieve(r, nil)
		m.Data = r.Data
		m.Pack()

		io.Copy(w, m)
	})
}
