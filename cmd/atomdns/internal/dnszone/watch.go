package dnszone

import (
	"context"
	"path"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watch watches the containing directory of file, and executes fn once a write event happens that matches file.
// Specifically it performs fn() after fsnotify.Write and fsnotify.Rename.
func Watch(ctx context.Context, file string, fn func()) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	file = path.Clean(file)

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					continue
				}
				switch {

				case event.Has(fsnotify.Write):
					fallthrough
				case event.Has(fsnotify.Rename):
					time.Sleep(2 * time.Second)

					if file == path.Clean(event.Name) {
						fn()
					}

				case event.Has(fsnotify.Remove):
				case event.Has(fsnotify.Create):
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
