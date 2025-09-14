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
	"codeberg.org/miekg/dns/cmd/testserv/handlers/unpack"
	"codeberg.org/miekg/dns/cmd/testserv/internal/conffile"
	"codeberg.org/miekg/dns/cmd/testserv/internal/dnsserver"
	"codeberg.org/miekg/dns/dnsutil"
)

func parse(mux *dns.ServeMux, conf string) (*global.Global, error) {
	f, _ := os.Open(conf)
	defer f.Close()
	blocks, err := conffile.Parse(conf, f, nil)
	if err != nil {
		return nil, err
	}

	global := &global.Global{}
	for _, b := range blocks {
		if b.Keys != nil {
			continue
		}
		for _, dir := range b.Directives {
			d := conffile.NewDispenser(conf, nil, b.Tokens[dir])
			err := global.Setup(d)
			if err != nil {
				return global, fmt.Errorf("could not parse global config: %s", err)
			}
		}
		break
	}

	for _, b := range blocks {
		if b.Keys == nil {
			continue
		}
		// prepend unpack to start the chain
		hs := []handlers.Handler{new(unpack.Unpack)}
		names := []string{}
		for _, name := range b.Directives {
			names = append(names, name)
			newFn, ok := handlers.StringToHandler[name]
			if !ok {
				return global, fmt.Errorf("unknown handler: %s", name)
			}
			handler := newFn()
			if s, ok := handler.(handlers.Setupper); ok {
				co := dnsserver.Controller{
					Dispenser: conffile.NewDispenser(conf, b.Keys, b.Tokens[name]),
					Global:    global,
				}
				err := s.Setup(co)
				if err != nil {
					return global, handler.Err(err)
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
	return global, nil
}
