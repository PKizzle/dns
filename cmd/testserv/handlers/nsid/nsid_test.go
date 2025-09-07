package nsid

import (
	"context"
	"encoding/hex"
	"log/slog"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/whoami"
	"codeberg.org/miekg/dns/dnstest"
)

func TestNsid(t *testing.T) {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	in := "Use the force"
	h := &Nsid{Data: hex.EncodeToString([]byte(in))}
	r := dns.NewMsg("whoami.example.org.", dns.TypeA)
	r.ID = 3
	r.Pseudo = []dns.RR{&dns.NSID{}}
	r.Pack()

	w := dnstest.NewRecorder(&dnstest.ResponseWriter{})
	next := new(whoami.Whoami).HandlerFunc(nil)
	h.HandlerFunc(next).ServeDNS(context.TODO(), w, r)

	if len(w.Msg.Pseudo) != 1 {
		t.Fatal("expected pseudo section")
	}
	if w.Msg.Pseudo[0].(*dns.NSID).Nsid != hex.EncodeToString([]byte(in)) {
		t.Fatalf("expected NSID rr contain: %s", in)
	}
}
