package dnstest

import (
	"io"
	"net"
	"testing"

	"codeberg.org/miekg/dns"
)

type responseWriter struct{ dns.ResponseWriter }

func (r *responseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (r *responseWriter) Conn() net.Conn              { return nil }

func TestRecord(t *testing.T) {
	w := &responseWriter{}
	recorder := NewRecorder(w)

	m := new(dns.Msg)
	m.Question = []dns.RR{&dns.TXT{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET}}}
	m.Pack()

	io.Copy(recorder, m)

	if x := recorder.Msg.Question[0].Header().Name; x != "miek.nl." {
		t.Errorf("expected %s, got %s", "miek.nl.", x)
	}
}
