package dbfile

import (
	"context"
	"io"
	"slices"
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
			if !slices.Contains(d.From.IPs, dnsutil.RemoteIP(w)) {
				return // ignore request
			}
			m := new(dns.Msg)
			dnsutil.SetReply(m, r)
			m.Authoritative = true
			m.Data = r.Data
			m.Pack()
			io.Copy(w, m)

			err := d.TransferIn(dns.Zone(ctx))
			if err != nil {
				// ...
			}
			return // ignore request
		}
		if _, qtype := dnsutil.Question(r); qtype == dns.TypeAXFR || qtype == dns.TypeIXFR {
			if d.To == nil {
				m := new(dns.Msg)
				dnsutil.SetReply(m, r)
				m.Rcode = dns.RcodeRefused
				m.Data = r.Data

				m.Pack()
				io.Copy(w, m)
				return
			}
			if err := d.TransferOut(ctx, w, r); err != nil {
				log.Debug("Error while transfering out: " + err.Error())
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
