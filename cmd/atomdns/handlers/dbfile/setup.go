package dbfile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"codeberg.org/miekg/dns/dnsutil"
)

func (d *Dbfile) Setup(co *dnsserver.Controller) error {
	d.Zones = map[string]*zone.Zone{}
	d.ctx, d.cancel = context.WithCancel(context.Background())

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
	if len(co.Keys()) > 1 && len(d.From.IPs) > 0 {
		return co.Errf("when transferring from, there can only be a single origin, got: %s", strings.Join(co.Keys(), ", "))
	}

	for _, z := range co.Keys() {
		d.Zones[dnsutil.Canonical(z)] = zone.New(z, d.Path)
	}
	co.OnStartup(func() error {
		log.Info("Startup", "reload", filepath.Base(d.Path))
		d.RLock()
		for _, z := range d.Zones {
			_, err := os.Stat(z.Path)
			if errors.Is(err, os.ErrNotExist) {
				log.Warn(fmt.Sprintf("Zone %q in file %q does not exist (yet?)", z.Origin, filepath.Base(z.Path)))
				continue
			}
			if err := z.Load(); err != nil {
				return co.Err(err.Error())
			}
		}
		d.RUnlock()
		return d.Reload()
	})
	co.OnStartup(func() error {
		if d.From == nil || len(d.From.IPs) == 0 {
			return nil
		}
		d.RLock()
		for _, z := range d.Zones {
			log.Info("Startup", "retransfer", "origin", z.Origin, "file", filepath.Base(d.Path))
			err := d.TransferIn(z.Origin)
			if err != nil {
				log.Error(fmt.Sprintf("Failed transfer of zone %q in %q: %s", z.Origin, d.Path, err))
			}
			break
		}
		d.RUnlock()
		return d.Retransfer()
	})
	co.OnShutdown(func() error {
		log.Info("Shutdown", "reload", filepath.Base(d.Path))
		d.cancel()
		return nil
	})
	co.OnShutdown(func() error {
		if d.From == nil || len(d.From.IPs) == 0 {
			return nil
		}
		log.Info("Shutdown", "retransfer", "file", filepath.Base(d.Path))
		d.cancel()
		return nil
	})

	return nil
}
