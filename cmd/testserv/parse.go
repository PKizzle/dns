package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/testserv/conffile"
	"codeberg.org/miekg/dns/cmd/testserv/handlers"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/refused"
	"codeberg.org/miekg/dns/dnsutil"
)

func parse(mux *dns.ServeMux) error {
	f, _ := os.Open("conf")
	defer f.Close()
	blocks, err := conffile.Parse("conf", f, nil)
	if err != nil {
		log.Fatal(err)
	}

	for _, b := range blocks {
		hs := []handlers.Handler{}
		names := []string{}
		if b.Keys == nil {
			// TODO: global
		}
		for name, tokens := range b.Tokens {
			names = append(names, name)
			newFn, ok := handlers.StringToHandler[name]
			if !ok {
				return fmt.Errorf("unknown handler: %s", name)
			}
			handler := newFn()
			if s, ok := handler.(handlers.Setupper); ok {
				d := conffile.NewDispenser("conf", b.Keys, tokens)
				err := s.Setup(d)
				if err != nil {
					return fmt.Errorf("could not parse config for handler: %q: %s", name, err)
				}
			}
			hs = append(hs, handler)
		}
		// append refuse as a guard
		hs = append(hs, new(refused.Refused))
		// for all keys (=zones) add this chain
		for _, k := range b.Keys {
			k = dnsutil.Fqdn(k)
			log.Printf("%s with %q\n", k, strings.Join(names, ","))
			mux.HandleFunc(k, handlers.Compile(hs))
		}
	}
	return nil
}
