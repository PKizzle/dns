package handlers

import (
	"context"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/any"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/chaos"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/log"
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

// todo generate: lowercase type name of the handler is the name.
var StringToHandler = map[string]func() Handler{
	"chaos":   func() Handler { return new(chaos.Chaos) },
	"log":     func() Handler { return new(log.Log) },
	"any":     func() Handler { return new(any.Any) },
	"whoami":  func() Handler { return new(whoami.Whoami) },
	"twiddle": func() Handler { return new(twiddle.Twiddle) },
}

// Compile takes the base http.HandlerFunc h and wraps it around the given list of Handlers h.
func Compile(h []string) dns.HandlerFunc {
	if len(h) < 1 {
		panic("testserv: need something compile")
	}

	stack := make([]Handler, len(h))
	for i := range h {
		newFn := StringToHandler[h[i]]
		stack[i] = newFn()
	}

	wrapped := func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) { /*mux does this too */ }
	// loop in reverse to preserve middleware order
	for i := len(h) - 1; i >= 0; i-- {
		wrapped = stack[i].HandlerFunc(wrapped)
	}

	return wrapped
}
