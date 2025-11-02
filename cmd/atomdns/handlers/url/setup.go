package url

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"codeberg.org/miekg/dns/dnsutil"
)

func (u *Url) Setup(co *dnsserver.Controller) error {
	u.Zones = map[string]*zone.Zone{}
	u.ctx, u.cancel = context.WithCancel(context.Background())

	if co.Next() {
		if !co.Next() {
			return co.ArgErr()
		}
		u.URL = co.Val()
		if !co.Next() {
			return co.ArgErr()
		}
		if !strings.HasPrefix(u.URL, "http://") && !strings.HasPrefix(u.URL, "https://") {
			u.URL = "https://" + u.URL
		}

		u.Path = co.Path()
	}

	for _, z := range co.Keys() {
		u.Zones[dnsutil.Canonical(z)] = zone.New(z, u.Path)
	}
	co.OnStartup(func() error {
		log.Info("Startup", "reload", filepath.Base(u.Path))
		u.RLock()
		zones := maps.Values(u.Zones)
		u.RUnlock()
		for z := range zones {
			alog := log.With(slog.String("zone", z.Origin()), slog.String("file", filepath.Base(z.Path)))
			_, err := os.Stat(z.Path)
			if errors.Is(err, os.ErrNotExist) {
				alog.Warn("Waiting for zone to appear")
				continue
			}
			if err := z.Load(); err != nil {
				return co.Err(err.Error())
			}
		}
		return u.Reload()
	})
	co.OnStartup(func() error {
		log.Info("Startup", "url", u.URL, "file", filepath.Base(u.Path))

		go func() {
			err := u.Fetch()
			if err != nil {
				alog := log.With(slog.String("url", u.URL), slog.String("file", filepath.Base(u.Path)))
				alog.Error("Failed to fetch", Err(err))
			}
		}()
		return u.Refetch()
	})

	co.OnShutdown(func() error {
		log.Info("Shutdown", "reload", filepath.Base(u.Path))
		u.cancel()
		return nil
	})
	co.OnShutdown(func() error {
		log.Info("Shutdown", "refetch", filepath.Base(u.URL))
		u.cancel()
		return nil
	})

	return nil
}
