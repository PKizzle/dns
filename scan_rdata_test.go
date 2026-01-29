package dns

import (
	"testing"

	"codeberg.org/miekg/dns/rdata"
)

func TestNewData(t *testing.T) {
	s := "10 mx.miek.nl"
	rd, err := NewData(TypeMX, s, ".")
	if err != nil {
		t.Fatal(err)
	}
	mx := rd.(rdata.MX)
	if mx.Preference != 10 {
		t.Fatalf("expected 10, got %d", mx.Preference)
	}
	if mx.Mx != "mx.miek.nl." {
		t.Fatalf("expected mx.miek.nl., got %s", mx.Mx)
	}
}
