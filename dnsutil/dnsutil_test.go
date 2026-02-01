package dnsutil

import (
	"testing"
)

func TestTrim(t *testing.T) {
	testcases := []struct {
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

	for i, tc := range testcases {
		got := Trim(Fqdn(tc.qname), Fqdn(tc.zone))
		if got != tc.expected {
			t.Errorf("test %d, expected %s, got %s", i, tc.expected, got)
		}
	}
}

func TestIsFqdn(t *testing.T) {
	testcases := []struct {
		in       string
		expected bool
	}{
		{"miek.nl", false},
		{"miek.nl.", true},
		{"miek.nl\\.", true},
		{"miek.nl\\\\.", true},
		{"miek.n\\..", true},
	}
	for i, tc := range testcases {
		got := IsFqdn(tc.in)
		if got != tc.expected {
			t.Errorf("test %d, %s, expected %t, got %t", i, tc.in, tc.expected, got)
		}
	}
}

func TestRandomize(t *testing.T) {
	testcases := []string{
		"www.example.org.",
		"www.EXAM__PLE.org.",
		"www.Example1223.org.",
		"www.examPle.^$^$a.%orG.",
	}
	for _, tc := range testcases {
		rand := Randomize(tc)
		if rand == tc {
			t.Fatalf("expected randomized string to not be equal to input: %s", tc)
		}
	}
}
