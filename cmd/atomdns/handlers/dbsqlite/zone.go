package dbsqlite

import (
	"fmt"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
	"github.com/jmoiron/sqlx"
)

type Zone struct {
	db     *sqlx.DB
	Origin string
	Labels int
}

var _ dbfile.Interface = &Zone{}

// RR is the data we stored in the rrs table.
type RR struct {
	Name string
	Type string
	Data string
	TTL  int
}

func (z *Zone) Load() error            { return nil }
func (z *Zone) Set(_ zone.Node) string { return "" }

func (z *Zone) Walk(func(zone.Node) bool) {
}

func (z *Zone) AuthoritativeWalk(func(zone.Node, bool) bool) {
}

func (z *Zone) Previous(name string) zone.Node {
	prevs := []string{}
	err := z.db.Select(&prevs, "SELECT name FROM rrs WHERE name < ? COLLATE canonical ORDER BY name COLLATE canonical DESC LIMIT 1", name)
	if err != nil {
		return zone.Node{}
	}
	node, _ := z.Get(prevs[0])
	return node
}

func (z *Zone) Get(name string) (zone.Node, bool) {
	// Get will get name, if that doesn't return anything we do like '%.<name>' this is twofold: get one for
	// wildcards, and if we get a bunch of _longer_ names we know there are empty non-terminal. TODO(miek):
	// figure out how exactly.

	// TODO(miek): this probably warrants a cache that does binary caching
	// But the cache design needs to take into account nxdomain, and do that efficiently.

	rrs := []RR{}
	err := z.Select(&rrs, "SELECT * FROM rrs WHERE name = ?", name)
	if err != nil {
		return zone.Node{}, false
	}

	// If deemed OK
	node := zone.Node{Name: name, RRs: make([]dns.RR, 0, len(rrs))}
	sb := strings.Builder{}
	for _, rr := range rrs {
		sb.WriteString(rr.Name)
		sb.WriteByte(' ')
		sb.WriteString(strconv.Itoa(rr.TTL))
		sb.WriteByte(' ')
		sb.WriteString(rr.Type)
		sb.WriteByte(' ')
		sb.WriteString(rr.Data)
		sb.WriteByte('\n')
		rr1, err := dns.New(sb.String())
		if err != nil {
			log.Debug(fmt.Sprintf("Failed to convert DB RR to actual RR: %s: %s", sb.String(), err))
			sb.Reset()
			continue
		}
		node.RRs = append(node.RRs, rr1)
		sb.Reset()
	}
	return node, true
}

func (z *Zone) Apex() zone.Node {
	node, _ := z.Get(z.Origin)
	return node
}

func (z *Zone) Select(rrs *[]RR, query string, args ...any) error {
	return z.db.Select(rrs, query, args...)
}

func (d *Dbsqlite) Count() int {
	ints := []int{}
	if err := d.db.Select(&ints, "SELECT COUNT(*) FROM rrs"); err != nil {
		return 0
	}
	return ints[0]
}

func (d *Dbsqlite) Origins() []string {
	origins := []string{}
	d.db.Select(&origins,
		`SELECT DISTINCT name FROM rrs r1
WHERE NOT EXISTS (
  SELECT 1 FROM rrs r2
  WHERE r1.name LIKE '%.' || r2.name AND r1.name != r2.name
) ORDER BY name COLLATE canonical`)
	return origins
}
