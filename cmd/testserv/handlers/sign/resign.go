package sign

import (
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Resign launches a resign routine that listens for _write_ events to the origin zone files and resigns them.
func (s *Sign) Resign() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	ticker := time.NewTicker(5 * time.Hour)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				log.Debug("Zone watch event", "file", filepath.Base(event.Name))
				if !ok {
					continue
				}
				switch {
				case event.Has(fsnotify.Write):
					fallthrough
				case event.Has(fsnotify.Create):
					fallthrough
				case event.Has(fsnotify.Rename):
					fallthrough
				case event.Has(fsnotify.Remove):
					// See comment in dbfile/reload.go
					time.Sleep(2 * time.Second)

					// check which zone needs resigning
					for _, z := range s.Zones {
						if z.Path == event.Name {
						}
					}
				default:
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					continue
				}
				log.Debug("Zone watch event error", "err", err)
			case <-ticker.C:
			// check zone and resign if needed

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
