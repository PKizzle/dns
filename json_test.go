package dns

import (
	"testing"
)

func TestMarshal(t *testing.T) {
	// tojson
	rr0 := dnstestNew("www.example.org. IN A 127.0.0.1")
	rr1 := dnstestNew("www.example.org. IN A 127.0.0.2")
	jsonb, _ := MarshalJSON(rr0, rr1)

	// fromjson
	rrs, err := UnmarshalJSON(jsonb)
	if err != nil {
		t.Fatal(err)
	}
	println(string(jsonb))

	if !Equal(rrs[0], rr0) {
		t.Fatalf("expected %s and %s to be equal", rrs[0], rr0)
	}
	if !Equal(rrs[1], rr1) {
		t.Fatalf("expected %s and %s to be equal", rrs[1], rr1)
	}
}
