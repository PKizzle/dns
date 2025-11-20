// package dnsctx helps with setting and getting data from the context of the current query.
package dnsctx

import (
	"context"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

// Func is a function that can be set in the context and operates on a [dns.Msg].
type Func func(*dns.Msg) *dns.Msg

// WithFuncValue set the Func f in the context under the key <handler>/msgfunc.
func WithFuncValue(ctx context.Context, handler string, f Func) context.Context {
	return context.WithValue(ctx, funckey(handler), f)
}

// funckey returns the string value for the Func in the context.
func funckey(s string) string { return s + "/msgfunc" }

// Funcs iterates over all handlers and run the functions that are set in the context over the message. The possibly
// modified message is returned.
func Funcs(ctx context.Context, m *dns.Msg) *dns.Msg {
	for _, h := range dnsserver.Handlers {
		key := funckey(h)
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

// WithValue stores value under the string value key, key must contain a slash and be formatted like
// "<handler>/xxx". If key does not contain a slash, this function is noop.
func WithValue(ctx context.Context, key string, value any) context.Context {
	if !strings.Contains(key, "/") {
		return ctx
	}
	return context.WithValue(ctx, key, value)
}

// Ctx returns the data under key. If key does not contain a slash nil is returned.
func Ctx(ctx context.Context, key string) any {
	if !strings.Contains(key, "/") {
		return ""
	}
	v := ctx.Value(key)
	if v == nil {
		return nil
	}
	return v
}
