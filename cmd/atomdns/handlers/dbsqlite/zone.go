package dbsqlite

import (
	"database/sql"

	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
)

type Zone struct {
	db *sql.DB
}

func (z *Zone) Load() error { return nil }

func (z *Zone) Get(name string) (zone.Node, bool) {
	// Get will get name, if that doesn't return anything we do like '%.<name>' this is twofold: get one for
	// wildcards, and if we get a bunch of _longer_ names we know there are empty non-terminal. TODO(miek):
	// figure out how exactly.

	return zone.Node{}, false
}
