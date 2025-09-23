package dbsqlite

import (
	"os"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/jmoiron/sqlx"
	"modernc.org/sqlite"
)

func (d *Dbsqlite) Setup(co *dnsserver.Controller) error {
	d.Zones = map[string]*Zone{}
	if !co.NextArg() {
		return co.ArgErr()
	}
	d.Path = co.Val()
	if co.Next() {
		d.Path = co.Val()
	}
	sqlite.RegisterCollationUtf8("canonical", func(left, right string) int { return dns.CompareName(left, right) })

	co.OnStartup(func() error {
		log.Info("Startup", "database", d.Path)
		_, err := os.OpenFile("db", os.O_CREATE, 0660)
		db, err := sqlx.Open("sqlite", "db")
		if err != nil {
			return err
		}
		d.db = db
		for _, z := range co.Keys() {
			d.Zones[dnsutil.Canonical(z)] = &Zone{db: db, labels: dnsutil.Labels(z), origin: dnsutil.Canonical(z)}
		}
		_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS rrs (
name  VARCHAR(255),
type  VARCHAR(10),
data  VARCHAR(65535),
ttl   INTEGER,
UNIQUE (name, type, data)
);
	`)
		return err
	})
	co.OnStartup(func() error {
		log.Info("Startup", "database", d.Path, "records", d.Count(), "origins", strings.Join(d.Origins(), ","))
		return nil
	})
	co.OnShutdown(func() error {
		log.Info("Shutdown", "database", d.Path)
		d.db.Close()
		return nil
	})

	return nil
}
