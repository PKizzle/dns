package nsid_test

import (
	"context"
	"encoding/hex"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/atomtest"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/nsid"
	"codeberg.org/miekg/dns/dnstest"
)

func TestNsid(t *testing.T) {
	in := "Use the force"
	n := &nsid.Nsid{Data: hex.EncodeToString([]byte(in))}

	r := dns.NewMsg("whoami.example.org.", dns.TypeA)
	r.ID = 3
	r.Pseudo = []dns.RR{&dns.NSID{}}
	r.Pack()

	w := dnstest.NewRecorder(&dnstest.ResponseWriter{})
	n.HandlerFunc(atomtest.Echo).ServeDNS(context.TODO(), w, r)

	if len(w.Msg.Pseudo) != 1 {
		t.Fatal("expected pseudo section")
	}
	if w.Msg.Pseudo[0].(*dns.NSID).Nsid != hex.EncodeToString([]byte(in)) {
		t.Fatalf("expected NSID RR contain: %s", in)
	}
}
