package generate

import (
	"log"
	"os"
	"path/filepath"
)

func Handlers(path ...string) ([]string, error) {
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
		// some handlers that are "special"
		if d.Name() == "global" {
			continue
		}
		if d.Name() == "unpack" {
			continue
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
