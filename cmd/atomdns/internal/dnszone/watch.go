package dnszone

import (
	"context"
	"path"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watch watches the containing directory of file, and executes fn once a write event happens that matches file.
func Watch(ctx context.Context, file string, fn func()) error {
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

					if file == path.Clean(event.Name) {
						fn()
					}
				default:
				}
			case _, ok := <-watcher.Errors:
				if !ok {
					continue
				}
			case <-ctx.Done():
				watcher.Close()
				return
			}
		}
	}()

	watcher.Add(filepath.Dir(file))
	return nil
}
