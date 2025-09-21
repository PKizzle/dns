package dbsqlite

import (
	"database/sql"
	"log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"modernc.org/sqlite"
)

func (d *Dbsqlite) Setup(co *dnsserver.Controller) error {
	db, err := sql.Open("sqlite", "db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Verify connection
	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}
	sqlite.RegisterCollationUtf8("canonical", func(left, right string) int { return dns.CompareName(left, right) })
	rrs := []RR{}
	err := db.Select(&rrs, "SELECT * FROM records")
	return nil
}

type RR struct {
	name string
	typ  string `db:"type"`
	data string
	ttl  int
}
