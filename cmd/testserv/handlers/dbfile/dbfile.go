package dbfile

import (
	"context"
	"io"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/dbfile/zone"
)

type Dbfile struct {
	Path           string
	Reload         time.Duration
	DisableMinimal bool

	// Zones holds all the zone this instance of Dbfile is called for.
	Zones map[string]*zone.Zone
}

func (d *Dbfile) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		z := d.Zones[dns.Zone(ctx)]

		m := z.Get(r)
		m.Data = r.Data
		m.Pack()

		io.Copy(w, m)
	})
}
