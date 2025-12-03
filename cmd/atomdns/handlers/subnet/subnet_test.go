package subnet_test

import (
	"context"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/subnet"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
)

func TestSubnet(t *testing.T) {
	h := &subnet.Subnet{}

	ecs := &dns.SUBNET{Family: dnsutil.IPv4Family, SourceNetmask: 32, Address: dnstest.IPv4}
	r := dns.NewMsg("whoami.example.org.", dns.TypeA)
	r.ID = 3
	r.Pseudo = []dns.RR{ecs}
	r.Pack()

	w := dnstest.NewRecorder(&dnstest.ResponseWriter{})
	next := dns.HandlerFunc(func(ctx context.Context, _ dns.ResponseWriter, _ *dns.Msg) {
		address := dnsctx.Value(ctx, "subnet/address")
		if address == nil {
			t.Fatal("expected subnet/address, got none")
		}
		if address.(string) != dnstest.IPv4.String() {
			t.Fatalf("expected %s, got %s", dnstest.IPv4.String(), address.(string))
		}
	},
	)
	ctx := context.TODO()
	h.HandlerFunc(next).ServeDNS(ctx, w, r)
}
