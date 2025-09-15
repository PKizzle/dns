package sign

import (
	"fmt"
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
				if !ok {
					continue
				}
				switch {
				case event.Has(fsnotify.Write):
					// see dbfile/reload.go for why we wait
					time.Sleep(2 * time.Second)
					for _, z := range s.Zones {
						log.Info(fmt.Sprintf("Zone write event seen for %q in %q", z.Origin, filepath.Base(event.Name)))
						if z.Path == event.Name {
							zs, err := s.Sign(z.Origin)
							if err != nil {
								log.Error(fmt.Sprintf("Failed resign of zone %q in %q: %s", z.Origin, filepath.Base(event.Name), err))
								break
							}
							if err := s.Write(zs); err != nil {
								log.Error(fmt.Sprintf("Failed resign of zone %q in %q: %s", z.Origin, filepath.Base(event.Name), err))
								break
							}
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
				for _, z := range s.Zones {
					zs, err := s.Sign(z.Origin)
					if err != nil {
						log.Error(fmt.Sprintf("Failed resign of zone %q in %q: %s", z.Origin, filepath.Base(z.Path), err))
						continue
					}
					if err := s.Write(zs); err != nil {
						log.Error(fmt.Sprintf("Failed resign of zone %q in %q: %s", z.Origin, filepath.Base(z.Path), err))
						continue
					}
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
