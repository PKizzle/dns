package dbfile

import (
	"context"
	"fmt"
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

			d.RLock()
			z := d.Zones[dns.Zone(ctx)]
			d.RUnlock()
			apex := z.Apex()
			serial := uint32(0)
			for _, rr := range apex.RRs {
				if s, ok := rr.(*dns.SOA); ok {
					serial = s.Serial
					break
				}
			}
			if !d.From.AvailableFrom(z.Origin, serial) {
				log.Warn(fmt.Sprintf("Notify seen for %q, but no newer zone available", z.Origin))
				return
			}

			d.TransferIn(dns.Zone(ctx)) // TODO(miek): error handling
			return
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
