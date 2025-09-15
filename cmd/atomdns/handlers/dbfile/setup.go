package dbfile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"codeberg.org/miekg/dns/dnsutil"
)

func (d *Dbfile) Setup(co *dnsserver.Controller) error {
	d.Zones = map[string]*zone.Zone{}
	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.To, d.From = &Transfer{}, &Transfer{}

	if co.Next() {
		args := co.RemainingArgs()
		if len(args) != 1 {
			return co.ArgErr()
		}
		d.Path = args[0]
		if !filepath.IsAbs(d.Path) {
			d.Path = filepath.Join(co.Global.Root, d.Path)
		}
		for co.NextBlock(0) {
			switch co.Val() {
			case "transfer":
				if err := d.SetupTransfer(co); err != nil {
					return err
				}
			default:
				return co.ArgErr()
			}
		}
	}
	for _, z := range co.Keys() {
		d.Zones[dnsutil.Canonical(z)] = zone.New(z, d.Path)
	}
	co.OnStartup(func() error {
		log.Info("Startup: reload: " + filepath.Base(d.Path))
		for _, z := range d.Zones {
			_, err := os.Stat(z.Path)
			if errors.Is(err, os.ErrNotExist) {
				log.Warn(fmt.Sprintf("Zone %q in %q does not exist (yet?)", z.Origin, filepath.Base(z.Path)))
				continue
			}
			if err := z.Load(); err != nil {
				return co.Err(err.Error())
			}
		}
		return d.Reload()
	})
	co.OnShutdown(func() error {
		log.Info("Shutdown: reload")
		d.cancel()
		return nil
	})

	return nil
}
