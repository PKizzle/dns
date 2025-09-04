package handlers

import (
	"context"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/testserv/conffile"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/any"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/chaos"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/log"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/refused"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/twiddle"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/whoami"
)

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
// from the config file.
type Setupper interface {
	Setup(conffile.Dispenser) error
}

// todo generate: lowercase type name of the handler is the name.
var StringToHandler = map[string]func() Handler{
	"chaos":   func() Handler { return new(chaos.Chaos) },
	"log":     func() Handler { return new(log.Log) },
	"any":     func() Handler { return new(any.Any) },
	"whoami":  func() Handler { return new(whoami.Whoami) },
	"twiddle": func() Handler { return new(twiddle.Twiddle) },
	"refused": func() Handler { return new(refused.Refused) },
}

// Compile takes the Handlers hs and creates a wrapped handle func.
func Compile(hs []Handler) dns.HandlerFunc {
	if len(hs) < 1 {
		panic("testserv: need something compile")
	}

	wrapped := func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {}
	// loop in reverse to preserve middleware order
	for i := len(hs) - 1; i >= 0; i-- {
		wrapped = hs[i].HandlerFunc(wrapped)
	}
	return wrapped
}
