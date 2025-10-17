package dnsctx

import (
	"context"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

// Func is a function that can be set in the context woth [WithFuncValue] and operates on a [dns.Msg].
type Func func(*dns.Msg) *dns.Msg

// WithFuncValue set the Func f in the context under the key <name>/msgfunc.
func WithFuncValue(ctx context.Context, handler, f Func) context.Context {
	return context.WithValue(ctx, handler, f)
}

// Funcs iterates over all handlers and run the functions that are set in the context over the message. The possibly
// modified message is returned.
func Funcs(ctx context.Context, m *dns.Msg) *dns.Msg {
	for _, h := range dnsserver.Handlers {
		v := ctx.Value(h)
		if v == nil {
			continue
		}
		if f, ok := v.(Func); ok {
			m = f(m)
		}
	}
	return m
}
