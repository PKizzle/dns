package dnsutil

import (
	"testing"
)

func TestTrimZone(t *testing.T) {
	tests := []struct {
		qname    string
		zone     string
		expected string
	}{
		{"a.example.org", "example.org", "a"},
		{"a.b.example.org", "example.org", "a.b"},
		{"b.", ".", "b"},
		{"example.org", "example.org", ""},
		{"org", "example.org", ""},
	}

	for i, tc := range tests {
		got := Trim(Fqdn(tc.qname), Fqdn(tc.zone))
		if got != tc.expected {
			t.Errorf("Test %d, expected %s, got %s", i, tc.expected, got)
		}
	}
}

func TestIsFqdn(t *testing.T) {
	tests := []struct {
		in       string
		expected bool
	}{
		{"miek.nl", false},
		{"miek.nl.", true},
		{"miek.nl\\.", false},
		{"miek.nl\\\\.", true},
		{"miek.n\\..", true},
	}
	for i, tc := range tests {
		got := IsFqdn(tc.in)
		if got != tc.expected {
			t.Errorf("Test %d, %s, expected %t, got %t", i, tc.in, tc.expected, got)
		}
	}
}

func TestIsNameOpenEscape(t *testing.T) {
	if ok := IsName("example.net."); !ok {
		t.Fatalf("expected ok, but got not ok")
	}
	if ok := IsName("example.net\\"); ok {
		t.Fatalf("expected not ok, but got ok")
	}
}
