package dbfile

import (
	"fmt"
	"path/filepath"
	"time"

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
			case "reload":
				co.NextArg()
				dur, err := time.ParseDuration(co.Val())
				if err != nil {
					return co.PropErr(err)
				}
				if dur < time.Second*10 {
					return co.PropErr(fmt.Errorf("reload duration must be > 10s"))
				}
				d.Reload = dur
			case "minimal":
				co.NextArg()
				if co.Val() != "disable" {
					return co.PropErr(fmt.Errorf("only valid value is %q", "disable"))
				}
				d.DisableMinimal = true
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
		}
		return nil
	})

	return nil
}
