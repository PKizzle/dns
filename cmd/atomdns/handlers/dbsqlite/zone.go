package dbsqlite

import (
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
	"github.com/jmoiron/sqlx"
)

type Zone struct {
	db *sqlx.DB
}

// RR is the data we stored in the rrs table.
type RR struct {
	Name string
	Type string `db:"type"`
	Data string
	TTL  int
}

func (z *Zone) Load() error            { return nil }
func (z *Zone) Set(_ zone.Node) string { return "" }

func (z *Zone) Get(name string) (zone.Node, bool) {
	// Get will get name, if that doesn't return anything we do like '%.<name>' this is twofold: get one for
	// wildcards, and if we get a bunch of _longer_ names we know there are empty non-terminal. TODO(miek):
	// figure out how exactly.

	return zone.Node{}, false
}
