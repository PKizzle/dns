package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/testserv/handlers"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/global"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/refuse"
	"codeberg.org/miekg/dns/cmd/testserv/internal/conffile"
	"codeberg.org/miekg/dns/cmd/testserv/internal/dnsserver"
	"codeberg.org/miekg/dns/dnsutil"
)

func parse(mux *dns.ServeMux, conf string) error {
	f, _ := os.Open(conf)
	defer f.Close()
	blocks, err := conffile.Parse(conf, f, nil)
	if err != nil {
		return err
	}

	config := &global.Global{}
	for _, b := range blocks {
		if b.Keys != nil {
			continue
		}
		for _, dir := range b.Directives {
			d := conffile.NewDispenser(conf, nil, b.Tokens[dir])
			err := config.Setup(d)
			if err != nil {
				return fmt.Errorf("could not parse global config: %s", err)
			}
		}
		break
	}

	for _, b := range blocks {
		if b.Keys == nil {
			continue
		}
		hs := []handlers.Handler{}
		names := []string{}
		for _, name := range b.Directives {
			names = append(names, name)
			newFn, ok := handlers.StringToHandler[name]
			if !ok {
				return fmt.Errorf("unknown handler: %s", name)
			}
			handler := newFn()
			if s, ok := handler.(handlers.Setupper); ok {
				c := dnsserver.Controller{
					Dispenser: conffile.NewDispenser(conf, b.Keys, b.Tokens[name]),
					Config:    config,
				}
				err := s.Setup(c)
				if err != nil {
					return fmt.Errorf("could not parse config: %s", err)
				}
			}
			hs = append(hs, handler)
		}
		// append refuse as a guard
		hs = append(hs, new(refuse.Refuse))
		// for all keys (=zones) add this chain
		for _, k := range b.Keys {
			k = dnsutil.Fqdn(k)
			slog.Info(k, "handlers", strings.Join(names, ","))
			mux.HandleFunc(k, handlers.Compile(hs))
		}
	}
	return nil
}
