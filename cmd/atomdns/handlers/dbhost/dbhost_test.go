package dbhost

import (
	"context"
	"net"
	"slices"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/whoami"
	"codeberg.org/miekg/dns/dnstest"
)

func TestDbhost(t *testing.T) {
	h := &Dbhost{Path: "/etc/hosts"}
	h.Load()

	r := dns.NewMsg("localhost.", dns.TypeA)
	r.ID = 3
	r.Pack()

	w := dnstest.NewRecorder(&dnstest.ResponseWriter{})
	next := new(whoami.Whoami).HandlerFunc(nil)
	h.HandlerFunc(next).ServeDNS(context.TODO(), w, r)

	if x := w.Msg.Answer[0].(*dns.A).A; slices.Compare(x, net.IP([]byte{127, 0, 0, 1})) != 0 {
		t.Fatalf("expected %s, got %s", "127.0.0.1", x)
	}
}
