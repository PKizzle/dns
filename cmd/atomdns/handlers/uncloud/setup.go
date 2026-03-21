package uncloud

import (
	"context"
	"net"
	"path/filepath"
	"time"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/jmoiron/sqlx"
)

const defaultDuration = 30 * 24 * time.Hour

func (u *Uncloud) Setup(co *dnsserver.Controller) error {
	if len(co.Keys()) > 1 {
		return co.Errf("only a single zone is allowed")
	}

	if len(co.Keys()) > 0 { // for uncloud_test.go we need to guard this
		u.Name = dnsutil.Fqdn(co.Keys()[0])
	}

	addr := ":443"
	for co.Next() {
		if !co.NextArg() {
			return co.ArgErr()
		}
		u.Path = co.Path()

		for co.NextBlock(0) {
			switch co.Val() {
			case "addr":
				args, err := co.RemainingAddrs()
				if err != nil {
					return co.PropErr(err)
				}
				if len(args) != 1 {
					return co.ArgErr()

				}
				addr = args[0]
			default:
				return co.ArgErr()
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	co.OnStartup(func() error {

		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return u.Err(err)
		}
		go func() { u.Serve(ln) }()
		u.Listener = ln

		log().Info("Startup", "v1/domains", u.Listener.Addr(), "path", filepath.Base(u.Path))

		db, err := sqlx.Open("sqlite", u.Path)
		if err != nil {
			return u.Err(err)
		}
		u.db = db

		{
			if err := u.Purge(defaultDuration); err != nil {
				log().Debug("Purge failed", Err(err))
			}
			go func() {
				ticker := time.NewTicker(time.Hour)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						if err := u.Purge(defaultDuration); err != nil {
							log().Debug("Purge failed", Err(err))
						}

					case <-ctx.Done():
						return
					}
				}
			}()
		}
		return nil
	})
	co.OnShutdown(func() error {
		log().Info("Shutdown", "v1/domains", addr, "path", filepath.Base(u.Path))
		cancel()
		u.Listener.Close()
		u.db.Close()
		return nil
	})
	return nil
}
