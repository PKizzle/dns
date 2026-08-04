package dns_test

import (
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
)

func TestMarshalJSON(t *testing.T) {
	// tojson
	rr0 := dnstest.New("www.example.org. IN A 127.0.0.1")
	rr1 := dnstest.New("www.example.org. IN A 127.0.0.2")
	jsonb, _ := dns.MarshalJSON(rr0, rr1)

	// fromjson
	rrs, err := dns.UnmarshalJSON(jsonb)
	if err != nil {
		t.Fatal(err)
	}

	if !dns.Equal(rrs[0], rr0) {
		t.Fatalf("expected %s and %s to be equal", rrs[0], rr0)
	}
	if !dns.Equal(rrs[1], rr1) {
		t.Fatalf("expected %s and %s to be equal", rrs[1], rr1)
	}
}
