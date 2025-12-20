package dbhost

import (
	"context"
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/whoami"
	"codeberg.org/miekg/dns/dnstest"
)

func TestDbhost(t *testing.T) {
	d := &Dbhost{Path: "/etc/hosts"}
	d.Load()

	m := dns.NewMsg("localhost.", dns.TypeA)
	m.ID = 3
	m.Pack()

	tw := dnstest.NewRecorder(&dnstest.ResponseWriter{})
	next := new(whoami.Whoami).HandlerFunc(nil)
	d.HandlerFunc(next).ServeDNS(context.TODO(), tw, m)

	if x := tw.Msg.Answer[0].(*dns.A).Addr; x != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("expected %s, got %s", "127.0.0.1", x)
	}
}
