package dbfile

import (
	"context"
	"fmt"
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
			}
			log.Info(fmt.Sprintf("Notify from %s for %s: checking transfer", dnsutil.RemoteIP(w), dns.Zone(ctx)))
			// transfer in if needed
			ok, err := z.shouldTransfer()
			if ok {
				z.TransferIn()
			} else {
				log.Infof("Notify from %s for %s: no SOA serial increase seen", state.IP(), zone)
			}
			if err != nil {
				log.Warningf("Notify from %s for %s: failed primary check: %s", state.IP(), zone, err)
			}
			return dns.RcodeSuccess, nil
		}
		// log.Warningf("Dropping notify from %s for %s", state.IP(), zone)

		d.RLock()
		z := d.Zones[dns.Zone(ctx)]
		d.RUnlock()

		m := z.Retrieve(r, nil)
		m.Data = r.Data
		m.Pack()

		io.Copy(w, m)
	})
}
