package dbsqlite

import (
	"os"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"github.com/jmoiron/sqlx"
	"modernc.org/sqlite"
)

func (d *Dbsqlite) Setup(co *dnsserver.Controller) error {
	if !co.NextArg() {
		return co.ArgErr()
	}
	d.Path = co.Val()
	if co.Next() {
		d.Path = co.Val()
	}
	sqlite.MustRegisterCollationUtf8("canonical", func(left, right string) int { return dns.CompareName(left, right) })

	co.OnStartup(func() error {
		log.Info("Startup: database: " + d.Path)
		_, err := os.OpenFile("db", os.O_CREATE, 0660)
		db, err := sqlx.Open("sqlite", "db")
		if err != nil {
			return err
		}
		d.Zone = &Zone{db}
		_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS rrs (
name  VARCHAR(255),
type  VARCHAR(10),
data  VARCHAR(65535),
ttl   INTEGER,
UNIQUE (name, type, data)
);
	`)
		if err != nil {
			return err
		}
		return nil
	})
	co.OnShutdown(func() error {
		log.Info("Shutdown: database: " + d.Path)
		if d.Zone != nil {
			d.Zone.db.Close()
		}
		return nil
	})

	co.OnStartup(func() error {
		log.Info("Startup: test")

		d.Get("example.")
		return nil

	})
	/*
		err = db.Select(&rrs, "SELECT * FROM rrs")
		err = db.Select(&rrs, "SELECT * FROM rrs ORDER BY name COLLATE canonical")
	*/
	return nil
}
