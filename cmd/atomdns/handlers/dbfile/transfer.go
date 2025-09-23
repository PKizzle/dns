package dbfile

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
	"codeberg.org/miekg/dns/dnsutil"
)

func (d *Dbfile) HandlerFuncTransfer(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
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
}

func (d *Dbfile) TransferOut(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) error {
	w.Hijack()
	env := make(chan *dns.Envelope)
	c := dns.NewClient()
	var wg sync.WaitGroup

	wg.Go(func() {
		c.TransferOut(w, r, env)
		w.Close()
	})

	z := d.Zone(dns.Zone(ctx))

	apex := z.Apex()
	z.Walk(func(n dnszone.Node) bool {
		env <- &dns.Envelope{Answer: n.RRs}
		return true
	})
	for _, rr := range apex.RRs {
		if s, ok := rr.(*dns.SOA); ok {
			env <- &dns.Envelope{Answer: []dns.RR{s}}
		}
	}
	close(env)

	return nil
}

func (d *Dbfile) TransferIn(origin string) error {
	// save into temp file and then move this file over the dbfile path.
	c := dns.NewClient()
	m := dns.NewMsg(origin, dns.TypeAXFR)
	// compare SOA, we do an AXFR so that's an easy test, check for record. zone.Apex().

	f, err := os.CreateTemp(filepath.Dir(d.Path), "xxxxx.transferred")
	if err != nil {
		return err
	}
	defer f.Close()
	defer os.Remove(f.Name())

	for _, ip := range d.From.IPs {
		env, err := c.TransferIn(context.TODO(), m, "tcp", ip)
		if err != nil {
			continue
		}
		soa := 0
		for e := range env {
			if e.Error != nil {
				log.Warn(fmt.Sprintf("Error during transfer of zone %q in %q: %s", origin, d.Path, err))
			}
			for _, rr := range e.Answer {
				if _, ok := rr.(*dns.SOA); ok {
					soa++
					if soa > 1 {
						continue
					}
				}
				io.WriteString(f, rr.String())
				f.Write([]byte("\n"))
			}
		}
		break
	}
	f.Close()
	return os.Rename(f.Name(), d.Path)
}
