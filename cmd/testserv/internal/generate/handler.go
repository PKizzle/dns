package generate

import (
	"log"
	"os"
	"path/filepath"
)

func Handlers() ([]string, error) {
	subdirs, err := os.ReadDir(".")
	if err != nil {
		log.Fatal(err)
	}
	handlers := []string{}
	for _, d := range subdirs {
		if !d.IsDir() {
			continue
		}
		handler := filepath.Join(d.Name(), d.Name()+".go")
		types, err := Types(handler)
		if err != nil {
			return nil, err
		}
		handlers = append(handlers, types...)
	}
	return handlers, nil
}
