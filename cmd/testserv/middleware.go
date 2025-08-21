package main

import (
	"context"
	"log"

	"codeberg.org/miekg/dns"
)

// Log logs some output for each request received
func Log(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		log.Printf("Length: %d", r.Len())
		next.ServeDNS(ctx, w, r)
	})
}

type Plugin func(dns.HandlerFunc) dns.HandlerFunc

// Compile takes the base http.HandlerFunc h
// and wraps it around the given list of Plugin p.
func Compile(h dns.HandlerFunc, p []Plugin) dns.HandlerFunc {
	if len(p) < 1 {
		return h
	}

	wrapped := h

	// loop in reverse to preserve middleware order
	for i := len(p) - 1; i >= 0; i-- {
		wrapped = p[i](wrapped)
	}

	return wrapped
}
