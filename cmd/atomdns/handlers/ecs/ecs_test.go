package ecs_test

import (
	"context"
	"net"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/ecs"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
)

func TestEcs(t *testing.T) {
	h := &ecs.Ecs{}

	ecs := &dns.SUBNET{Family: dnsutil.IPv4Family, SourceNetmask: 32, Address: dnstest.IPv4}
	r := dns.NewMsg("whoami.example.org.", dns.TypeA)
	r.Pseudo = []dns.RR{ecs}
	r.Pack()

	w := dnstest.NewRecorder(&dnstest.ResponseWriter{})
	next := dns.HandlerFunc(func(ctx context.Context, _ dns.ResponseWriter, _ *dns.Msg) {
		address := dnsctx.Value(ctx, h.Key()+"/address")
		if address == nil {
			t.Fatal("expected ecs/address, got none")
		}
		if !address.(net.IP).Equal(dnstest.IPv4) {
			t.Fatalf("expected %s, got %s", dnstest.IPv4, address)
		}
	})
	ctx := context.TODO()
	h.HandlerFunc(next).ServeDNS(ctx, w, r)
}
