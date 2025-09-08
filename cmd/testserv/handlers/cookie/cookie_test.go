package cookie

import (
	"context"
	"encoding/hex"
	"hash/fnv"
	"io"
	"log/slog"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/whoami"
	"codeberg.org/miekg/dns/dnstest"
)

func TestCookie(t *testing.T) {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	h := &Cookie{Secret: "geheim"}

	f := fnv.New64()
	io.WriteString(f, "::1")
	io.WriteString(f, "::1")
	io.WriteString(f, "ook geheim")
	cookie := &dns.COOKIE{Cookie: hex.EncodeToString(f.Sum(nil))}

	r := dns.NewMsg("whoami.example.org.", dns.TypeA)
	r.ID = 3
	r.Pseudo = []dns.RR{cookie}
	r.Pack()

	w := dnstest.NewRecorder(&dnstest.ResponseWriter{})
	next := new(whoami.Whoami).HandlerFunc(nil)
	h.HandlerFunc(next).ServeDNS(context.TODO(), w, r)

	if len(w.Msg.Pseudo) != 1 {
		t.Fatal("expected pseudo section")
	}
	if _, ok := w.Msg.Pseudo[0].(*dns.COOKIE); !ok {
		t.Fatal("expected COOKIE RR")
	}
}
