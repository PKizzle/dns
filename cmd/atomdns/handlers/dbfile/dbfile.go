package dbfile

import (
	"context"
	"io"
	"sync"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
)

type Dbfile struct {
	Path string

	// Zones holds all the zone this instance of Dbfile is called for.
	Zones        map[string]*zone.Zone
	sync.RWMutex // protects Zones

	ctx    context.Context
	cancel context.CancelFunc

	To   *Transfer
	From *Transfer
}

// Transfer holds all the information to perform in incoming or outgoing zone transfer.
// The families from IP, Notifies and Sources will be matched upon sending the actual notifies.
type Transfer struct {
	IPs []string

	TSIG       *dns.TSIG
	TSIGSecret string // base64

	Notifies []string
	Sources  []string
}

func (d *Dbfile) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
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
