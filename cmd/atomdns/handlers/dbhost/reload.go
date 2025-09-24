package dbhost

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Reload launches a reload routine that listens for _write_ events to the hosts file.
func (d *Dbhost) Reload() error {
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

					if d.Path == event.Name {
						if err := d.Load(); err != nil {
							log.Error(fmt.Sprintf("Failed reload of hosts file in %q: %s", filepath.Base(event.Name), err))
							continue
						}
						log.Info(fmt.Sprintf("Reload of hosts file in %q successful", filepath.Base(event.Name)))
						break
					}
				default:
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					continue
				}
				log.Debug("Hosts file watch event error", "err", err)
			case <-d.ctx.Done():
				watcher.Close()
				return
			}
		}
	}()

	watcher.Add(filepath.Dir(d.Path))
	return nil
}
