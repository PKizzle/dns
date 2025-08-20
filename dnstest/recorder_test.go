package dnstest

import (
	"io"
	"testing"

	"codeberg.org/miekg/dns"
)

func TestRecorder(t *testing.T) {
	recorder := NewRecorder(nil)

	m := new(dns.Msg)
	m.Question = []dns.RR{&dns.TXT{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET}}}

	io.Copy(recorder, m)

	if x := recorder.Msgs[0].Question[0].Header().Name; x != "miek.nl." {
		t.Errorf("expected %s, got %s", "miek.nl.", x)
	}
}
