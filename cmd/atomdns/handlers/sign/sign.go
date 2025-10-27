// Package sign implements a zone signer as a hander.
package sign

import (
	"context"
	"log/slog"
	"path"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
)

type Sign struct {
	Path      string
	Directory string
	KeyPairs  []KeyPair
	pool      *dns.Pool

	Zones map[string]*zone.Zone
	ttl   uint32 // default ttl on all records

	ctx    context.Context
	cancel context.CancelFunc
}

func (s *Sign) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(
		func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) { next.ServeDNS(ctx, w, r) },
	)
}

// Various duration constants for signing of the zones.
const (
	expireDays = 9

	signatureExpire    = 32 * Day       // sign for 32 days
	signatureInception = -3 * time.Hour // -(2+1) hours, be sure to catch daylight saving time and such, jitter is subtracted

	inceptionJitter  = -18 * time.Hour // default max jitter for the inception
	expirationJitter = 100 * time.Hour // default max jitter for the expiration
)

const Day = 24 * time.Hour

const SignedBy = "Signed by atomdns, https://atomdns.miek.nl"

// Interval is the resign wake up interval.
const Interval = 5 * time.Hour

// Resign launches a resign routine that listens for _write_ events to the origin zone files and resigns them.
func (s *Sign) Resign() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	go func() {
		ticker := time.NewTicker(Interval)
		defer ticker.Stop()
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					continue
				}
				switch {
				case event.Has(fsnotify.Write):
					// see dbfile/reload.go for why we wait
					time.Sleep(2 * time.Second)
					for _, z := range s.Zones {
						alog := log.With(slog.String("zone", z.Origin()), slog.String("path", filepath.Base(event.Name)))
						if z.Path == path.Clean(event.Name) {
							zs, err := s.Sign(z.Origin())
							if err != nil {
								alog.Error("Failed to resign", Err(err))
								break
							}
							if err := s.Write(zs); err != nil {
								alog.Error("Failed to resign", Err(err))
								break
							}
							alog.Info("Successful resign")
						}
					}
				default:
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					continue
				}
				log.Debug("Zone watch event error", Err(err))
			case <-ticker.C:
				for _, z := range s.Zones {
					alog := log.With(slog.String("zone", z.Origin()), slog.String("path", filepath.Base(z.Path)))
					expired, err := s.Expired(z.Origin())
					if !expired {
						continue
					}
					zs, err := s.Sign(z.Origin())
					if err != nil {
						alog.Error("Failed to resign", Err(err))
						continue
					}
					if err := s.Write(zs); err != nil {
						alog.Error("Failed to resign", Err(err))
						continue
					}
					alog.Info("Successful resign")
				}

			case <-s.ctx.Done():
				watcher.Close()
				return
			}
		}
	}()

	for _, z := range s.Zones {
		watcher.Add(filepath.Dir(z.Path))
	}
	return nil
}
