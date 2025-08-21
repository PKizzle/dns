package main

import (
	"context"

	"codeberg.org/miekg/dns"
)

type Plugin interface {
	HandlerFunc(dns.HandlerFunc) dns.HandlerFunc
}

var StringToPlugin = map[string]func() Plugin{
	"chaos":  func() Plugin { return new(Chaos) },
	"log":    func() Plugin { return new(Log) },
	"any":    func() Plugin { return new(Any) },
	"whoami": func() Plugin { return new(Whoami) },
}

// Compile takes the base http.HandlerFunc h
// and wraps it around the given list of Plugin p.
func Compile(p []string) dns.HandlerFunc {
	if len(p) < 1 {
		panic("testserv: need something compile")
	}

	stack := make([]Plugin, len(p))
	for i := range p {
		newFn := StringToPlugin[p[i]]
		stack[i] = newFn()
	}

	wrapped := func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) { /*mux does this too */ }
	// loop in reverse to preserve middleware order
	for i := len(p) - 1; i >= 0; i-- {
		wrapped = stack[i].HandlerFunc(wrapped)
	}

	return wrapped
}
