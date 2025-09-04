package twiddle

import (
	"context"
	"io"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
)

// Twiddle will set the QR bit on a reply.
type Twiddle int

func (t *Twiddle) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		rec := dnstest.NewRecorder(w)
		//		rec.Discard = true

		next.ServeDNS(ctx, rec, r)

		m := rec.Msg
		m.Zero = true
		m.Response = false
		m.Pack()
		io.Copy(w, m)
	})
}
