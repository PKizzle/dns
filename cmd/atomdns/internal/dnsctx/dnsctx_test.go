package dnsctx

import (
	"context"
	"testing"

	"codeberg.org/miekg/dns"
)

type mockKeyer string

func (m mockKeyer) Key() string { return string(m) }

func TestFuncsOrder(t *testing.T) {
	ctx := context.Background()
	k1 := mockKeyer("h1")
	k2 := mockKeyer("h2")

	ctx = WithFunc(ctx, k1, func(m *dns.Msg) *dns.Msg {
		m.ID = 1
		return m
	})
	ctx = WithFunc(ctx, k2, func(m *dns.Msg) *dns.Msg {
		m.ID = 2
		return m
	})

	m := new(dns.Msg)
	m = Funcs(ctx, m)

	if m.ID != 2 {
		t.Errorf("Expected Id 2, got %d", m.ID)
	}
}

func TestWithFuncCompatibility(t *testing.T) {
	ctx := context.Background()
	k := mockKeyer("h1")
	f := func(m *dns.Msg) *dns.Msg { return m }

	ctx = WithFunc(ctx, k, f)

	// Test string key compatibility
	v := ctx.Value("h1/" + KeyMsgFunc)
	if v == nil {
		t.Error("Expected value under string key, got nil")
	}
}
