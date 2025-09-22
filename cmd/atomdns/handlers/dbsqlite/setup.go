package dbsqlite

import (
	"fmt"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"github.com/jmoiron/sqlx"
	"modernc.org/sqlite"
)

func (d *Dbsqlite) Setup(co *dnsserver.Controller) error {
	sqlite.MustRegisterCollationUtf8("canonical", func(left, right string) int { return dns.CompareName(left, right) })
	db, err := sqlx.Open("sqlite", "db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(`
CREATE TABLE rrs (
  name                  VARCHAR(255) COLLATE canonical,
  type                  VARCHAR(10),
  data                  VARCHAR(65535),
  ttl                   INTEGER DEFAULT 3600
);
	`)
	if err != nil {
		println("create", err.Error())
	}

	rrs := []RR{}
	err = db.Select(&rrs, "SELECT * FROM rrs")
	for _, rr := range rrs {
		fmt.Printf("%v\n", rr)
	}
	println("***")
	err = db.Select(&rrs, "SELECT * FROM rrs ORDER BY name COLLATE canonical")
	if err != nil {
		println(err.Error())
	}
	for _, rr := range rrs {
		fmt.Printf("%v\n", rr)
	}
	return nil
}

type RR struct {
	Name string
	Type string `db:"type"`
	Data string
	TTL  int
}
