package generate

import (
	"log"
	"os"
	"path/filepath"
)

// Handlers returns the handlers, except global and unpack.
func Handlers(path ...string) ([]string, error) { return handlers(false, path...) }

// AllHandlers returns all handlers.
func AllHandlers(path ...string) ([]string, error) { return handlers(true, path...) }

func handlers(all bool, path ...string) ([]string, error) {
	dir := "."
	if len(path) > 0 {
		dir = path[0]
	}

	subdirs, err := os.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}
	handlers := []string{}
	for _, d := range subdirs {
		if !d.IsDir() {
			continue
		}
		if !all {
			// some handlers that are "special"
			if d.Name() == "global" {
				continue
			}
			if d.Name() == "unpack" {
				continue
			}
		}
		handler := dir + "/" + filepath.Join(d.Name(), d.Name()+".go")
		types, err := Types(handler)
		if err != nil {
			return nil, err
		}
		handlers = append(handlers, types...)
	}
	return handlers, nil
}
