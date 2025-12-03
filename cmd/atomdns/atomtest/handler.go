package atomtest

import (
	"context"

	"codeberg.org/miekg/dns"
)

// Handler is a handler that execute Func inside the HandlerFunc method.
type Handler struct {
	Func dns.HandlerFunc
	Next bool // If Next is true the next handler in the chain is called.
}

func (h *Handler) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		h.Func(ctx, w, r)
		if h.Next {
			next.ServeDNS(ctx, w, r)
		}
	})
}
