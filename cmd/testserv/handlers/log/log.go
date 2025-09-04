package log

import (
	"context"
	"log"

	"codeberg.org/miekg/dns"
)

type Log int

// Log logs some output for each request received
func (l *Log) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		log.Printf("Length: %d", r.Len())
		next.ServeDNS(ctx, w, r)
	})
}
