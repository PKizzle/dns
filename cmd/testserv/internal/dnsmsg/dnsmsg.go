package dnsmsg

import (
	"context"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/testserv/internal/dnsserver"
)

type Func func(*dns.Msg) *dns.Msg

// msgfunckey returns the string value for the Func in the context.
func msgfunckey(s string) string { return s + "/msgfunc" }

// WithValue set the Func f in the context under the key handler.<name>/msgfunc.
func WithValue(ctx context.Context, handlerkey string, f Func) context.Context {
	return context.WithValue(ctx, msgfunckey(handlerkey), f)
}

// Funcs iterates over all handlers and run the functions that are set in the context over the message. The possibly
// modified message is returned.
func Funcs(ctx context.Context, m *dns.Msg) *dns.Msg {
	for _, h := range dnsserver.Handlers {
		key := msgfunckey(h)
		v := ctx.Value(key)
		if v == nil {
			continue
		}
		if f, ok := v.(Func); ok {
			m = f(m)
		}
	}
	return m
}
