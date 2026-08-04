package dnsjson

import (
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
)

func TestMarshal(t *testing.T) {
	// tojson
	rr0 := dnstest.New("www.example.org. IN A 127.0.0.1")
	rr1 := dnstest.New("www.example.org. IN A 127.0.0.2")
	jsonb, _ := Marshal(rr0, rr1)

	// fromjson
	rrs, err := Unmarshal(jsonb)
	if err != nil {
		t.Fatal(err)
	}
	println(string(jsonb))

	if !dns.Equal(rrs[0], rr0) {
		t.Fatalf("expected %s and %s to be equal", rrs[0], rr0)
	}
	if !dns.Equal(rrs[1], rr1) {
		t.Fatalf("expected %s and %s to be equal", rrs[1], rr1)
	}
}
