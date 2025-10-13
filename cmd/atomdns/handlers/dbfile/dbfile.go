package dbfile

import (
	"context"
	"io"
	"sync"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsmsg"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
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
		z := d.Zone(dns.Zone(ctx))
		if z == nil { // reload could have failed and we end up with no zone, call next to refuse
			next.ServeDNS(ctx, w, r)
			return
		}

		if r.Opcode == dns.OpcodeNotify {
			d.HandlerFuncNotify(ctx, w, r)
			return
		}
		if _, qtype := dnsutil.Question(r); qtype == dns.TypeAXFR || qtype == dns.TypeIXFR {
			d.HandlerFuncTransfer(ctx, w, r)
			return
		}

		m := dnszone.Retrieve(z, r, nil)

		m = dnsmsg.Funcs(ctx, m)
		if err := m.Pack(); err != nil {
			log.Debug("Pack failure", Err(err))
		}
		io.Copy(w, m)
	})
}

func (d *Dbfile) Zone(origin string) *zone.Zone {
	d.RLock()
	z := d.Zones[origin]
	d.RUnlock()
	return z
}
