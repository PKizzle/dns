package dnsmsg

import (
	"context"

	"codeberg.org/miekg/dns"
)

type Func func(*dns.Msg) *dns.Msg

// msgfunckey returns the string value for the Func in the context.
func msgfunckey(s string) string { return s + "/msgfunc" }

// WithValue set the Func f in the context under the key handler.<name>/msgfunc.
func WithValue(ctx context.Context, key string, f Func) context.Context {
	return context.WithValue(ctx, msgfunckey(key), f)
}

// Value returns the Func from the context.
func Value(ctx context.Context, key string) Func {
	return nil
}
