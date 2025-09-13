package generate

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"slices"
)

// Handlers returns the handlers, except global and unpack.
func Handlers(path ...string) ([]string, error) { return handlers(false, path...) }

// AllHandlers returns all handlers.
func AllHandlers(path ...string) ([]string, error) { return handlers(true, path...) }

var special = []string{"global", "unpack", "sign"}

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
			if slices.Contains(special, d.Name()) {
				continue
			}
		}
		handler := dir + "/" + filepath.Join(d.Name(), d.Name()+".go")
		types, err := Types(handler)
		if err != nil {
			return nil, err
		}
		// insanely crude check, but if there is a line that matches
		// 'HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {' in the file it _is_ an actual handler and
		// not only a Setupper - global is skipped then for example.
		p, _ := os.ReadFile(handler)
		if bytes.Contains(p, []byte("HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {")) {
			handlers = append(handlers, types...)
		}
	}
	return handlers, nil
}
