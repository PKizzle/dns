package handlers

import (
	"context"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/testserv/internal/dnsserver"
)

//go:generate go run string_generate.go
//go:generate go run err_generate.go

// A Handler is a dns.HandlerFunc that has a handler func (the next when to call in the middleware stack) as
// input and returns a handle func which is the handler itself.
//
// There are several types of handlers that you can implement, handlers that:
//
//   - observe, things like logging and metrics.
//   - modify the [dns.Msg] and then call the next handler, they can enrich the context or modify the message.
//   - call the next handler, wait for it to return and modify the [dns.Msg], think of setting TSIG or a DNS
//     cookie.
type Handler interface {
	HandlerFunc(dns.HandlerFunc) dns.HandlerFunc
}

// Setupper holds a single method that is called when this Handler has configuration that needs to be parsed
// from the config file. The options global.Global holds the server's global config.
type Setupper interface {
	Setup(dnsserver.Controller) error
}

// Compile takes the Handlers hs and creates a wrapped handle func.
func Compile(hs []Handler) dns.HandlerFunc {
	if len(hs) < 1 {
		panic("testserv: need something compile")
	}

	unpack := func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		err := r.Unpack()
		if err != nil {
			// slog.Debug... TODO
			return
		}
	}
	// loop in reverse to preserve middleware order
	for i := len(hs) - 1; i >= 0; i-- {
		unpack = hs[i].HandlerFunc(unpack)
	}
	return unpack
}
