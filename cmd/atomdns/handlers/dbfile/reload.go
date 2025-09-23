package dbfile

import (
	"fmt"
	"path/filepath"
	"time"

	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
	"github.com/fsnotify/fsnotify"
)

// Reload launches a reload routine that listens for _write_ events to the zone files.
func (d *Dbfile) Reload() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

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

					// check which zone needs reloading. Need RLOCK! But we also Lock later, this might clash...
					for _, z := range d.Zones {
						if z.Path == event.Name {
							z1 := zone.New(z.Origin(), event.Name)
							if err := z1.Load(); err != nil {
								log.Error(fmt.Sprintf("Failed reload of zone %q in %q: %s", z.Origin(), filepath.Base(event.Name), err))
								continue
							}
							d.Lock()
							d.Zones[z.Origin()] = z1
							d.Unlock()

							log.Info(fmt.Sprintf("Reload of zone %q in %q successful", z.Origin(), filepath.Base(event.Name)))
							go d.To.Notify(z.Origin())
							break
						}
					}
				default:
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					continue
				}
				log.Debug("Zone watch event error", "err", err)
			case <-d.ctx.Done():
				watcher.Close()
				return
			}
		}
	}()

	for _, z := range d.Zones {
		watcher.Add(filepath.Dir(z.Path))
	}
	return nil
}
