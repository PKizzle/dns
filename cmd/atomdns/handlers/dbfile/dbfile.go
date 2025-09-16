package dbfile

import (
	"context"
	"io"
	"sync"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
	"codeberg.org/miekg/dns/dnsutil"
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

func (d *Dbfile) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		if r.Opcode == dns.OpcodeNotify {
			if d.From.IsNotify(w) {
				m := new(dns.Msg)
				dnsutil.SetReply(m, r)
				m.Authoritative = true
				m.Data = r.Data
				m.Pack()
				io.Copy(w, m)

				err := d.TransferIn()
				if err != nil {
					// ...
				}
			}
			return // ignore request to avoid amplification
		}
		if _, qtype := dnsutil.Question(r); qtype == dns.TypeAXFR || qtype == dns.TypeIXFR {
			err := d.TransferOut()
			if err != nil {
				// ...
			}
			return
		}

		d.RLock()
		z := d.Zones[dns.Zone(ctx)]
		d.RUnlock()

		m := z.Retrieve(r, nil)
		m.Data = r.Data
		m.Pack()

		io.Copy(w, m)
	})
}
