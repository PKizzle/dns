package zone

import (
	"log"

	"github.com/fsnotify/fsnotify"
)

// Reload launches a reload routine that listens for _write_ events to the zone file. If seen the file
// reloads.
func (z *Zone) Reload() {
	watcher, err := fsnotify.NewWatcher()
	//	if err != nil {
	//		log.Fatal(err)
	//	}

	// Start listening for events.
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					println("!OK")
					return
				}
				// RENAME/CHMOD/WRITE
				// REMOVE/WRITE
				log.Println("event:", event)
				if event.Has(fsnotify.Write) {
					log.Println("modified file:", event.Name)
				}
				if event.Has(fsnotify.Remove) {
					log.Println("remove file:", event.Name)
					watcher.Add(z.Path)

				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("error:", err)
			case <-z.ctx.Done():
				watcher.Close()
				return
			}
		}
	}()

	// Add a path.
	err = watcher.Add(z.Path)
	if err != nil {
		log.Fatal(err)
	}
	return
}
