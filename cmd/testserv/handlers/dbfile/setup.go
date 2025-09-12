package dbfile

import (
	"path/filepath"

	"codeberg.org/miekg/dns/cmd/testserv/handlers/dbfile/zone"
	"codeberg.org/miekg/dns/cmd/testserv/internal/dnsserver"
	"codeberg.org/miekg/dns/dnsutil"
)

func (d *Dbfile) Setup(co dnsserver.Controller) error {
	d.Zones = map[string]*zone.Zone{}
	if co.Next() {
		args := co.RemainingArgs()
		if len(args) != 1 {
			return co.ArgErr()
		}
		d.Path = args[0]
		if !filepath.IsAbs(d.Path) {
			d.Path = filepath.Join(co.Global.Root, d.Path)
		}
		for co.NextBlock() {
			switch co.Val() {
			case "transfer":
				if err := d.SetupTransfer(co); err != nil {
					return err
				}
			default:
				return co.PropErr()
			}
		}
	}
	for _, z := range co.Keys() {
		d.Zones[dnsutil.Canonical(z)] = zone.New(z, d.Path)
	}
	co.OnStartup(func() error {
		for _, z := range d.Zones {
			if err := z.Load(); err != nil {
				return co.Err(err.Error())
			}
			z.Reload()
		}
		return nil
	})
	co.OnShutdown(func() error {
		for _, z := range d.Zones {
			z.Shutdown()
		}
		return nil
	})

	return nil
}
