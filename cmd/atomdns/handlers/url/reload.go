package url

import (
	"log/slog"
	"maps"
	"path"
	"path/filepath"
	"time"

	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
	"github.com/fsnotify/fsnotify"
)

// Reload launches a reload routine that listens for _write_ events to the zone files.
func (u *Url) Reload() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	// this is duplicated in dbfile and dbhost, could be moved to internal reload package. It does
	// need a way to perform extra functions after a reload.

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					continue
				}
				switch {
				case event.Has(fsnotify.Remove):
					// Not happy with this, but there is a race between the event and actually reading the
					// file, i.e. it might be empty, we don't really care how long the reload takes, as long
					// as it happens. Let do the dumbest thing you can do in a race, and wait a bit.
					time.Sleep(2 * time.Second)
					fallthrough
				case event.Has(fsnotify.Write):
					fallthrough
				case event.Has(fsnotify.Create):
					fallthrough
				case event.Has(fsnotify.Rename):

					u.RLock()
					zones := maps.Values(u.Zones)
					u.RUnlock()
					for z := range zones {
						if z.Path == path.Clean(event.Name) {
							alog := log.With(slog.String("zone", z.Origin()), slog.String("file", filepath.Base(event.Name)))
							z1 := zone.New(z.Origin(), event.Name)
							if err := z1.Load(); err != nil {
								alog.Error("Failed to reload", Err(err))
								continue
							}
							u.Lock()
							u.Zones[z.Origin()] = z1
							u.Unlock()

							alog.Info("Successful reload")
							break
						}
					}
				default:
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					continue
				}
				log.Debug("Zone watch event error", Err(err))
			case <-u.ctx.Done():
				watcher.Close()
				return
			}
		}
	}()

	for _, z := range u.Zones {
		watcher.Add(filepath.Dir(z.Path))
	}
	return nil
}
