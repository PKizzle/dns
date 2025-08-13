package dnsutil

import "testing"

func TestJoin(t *testing.T) {
	tests := []struct {
		in  []string
		out string
	}{
		{[]string{"bla", "bliep", "example", "org"}, "bla.bliep.example.org."},
		{[]string{"example", "."}, "example."},
		{[]string{"example", "org."}, "example.org."}, // technically we should not be called like this.
		{[]string{"."}, "."},
	}

	for i, tc := range tests {
		if x := Join(tc.in...); x != tc.out {
			t.Errorf("Test %d, expected %s, got %s", i, tc.out, x)
		}
	}
}

func TestSplit(t *testing.T) {
	splitter := map[string]int{
		"www.miek.nl.":    3,
		"www.miek.nl":     3,
		"www..miek.nl":    4,
		`www\.miek.nl.`:   2,
		`www\\.miek.nl.`:  3,
		`www\\\.miek.nl.`: 2,
		".":               0,
		"nl.":             1,
		"nl":              1,
		"com.":            1,
		".com.":           2,
	}
	for s, i := range splitter {
		if x := len(Split(s)); x != i {
			t.Errorf("labels should be %d, got %d: %s %v", i, x, s, Split(s))
		}
	}
}

func TestNext(t *testing.T) {
	type next struct {
		string
		int
	}
	nexts := map[next]int{
		{"", 1}:             0,
		{"www.miek.nl.", 0}: 4,
		{"www.miek.nl.", 4}: 9,
		{"www.miek.nl.", 9}: 12,
	}
	for s, i := range nexts {
		x, ok := Next(s.string, s.int)
		if i != x {
			t.Errorf("label should be %d, got %d, %t: next %d, %s", i, x, ok, s.int, s.string)
		}
	}
}

func TestPrev(t *testing.T) {
	type prev struct {
		string
		int
	}
	prever := map[prev]int{
		{"", 1}:             0,
		{"www.miek.nl.", 0}: 12,
		{"www.miek.nl.", 1}: 9,
		{"www.miek.nl.", 2}: 4,

		{"www.miek.nl", 0}: 11,
		{"www.miek.nl", 1}: 9,
		{"www.miek.nl", 2}: 4,

		{"www.miek.nl.", 5}: 0,
		{"www.miek.nl", 5}:  0,

		{"www.miek.nl.", 3}: 0,
		{"www.miek.nl", 3}:  0,
	}
	for s, i := range prever {
		x, ok := Prev(s.string, s.int)
		if i != x {
			t.Errorf("label should be %d, got %d, %t: previous %d, %s", i, x, ok, s.int, s.string)
		}
	}
}

func TestCount(t *testing.T) {
	splitter := map[string]int{
		"www.miek.nl.": 3,
		"www.miek.nl":  3,
		"nl":           1,
		".":            0,
	}
	for s, i := range splitter {
		x := Count(s)
		if x != i {
			t.Errorf("CountLabel should have %d, got %d", i, x)
		}
	}
}

func TestCanonical(t *testing.T) {
	for s, expect := range map[string]string{
		"":                 ".",
		".":                ".",
		"tld":              "tld.",
		"tld.":             "tld.",
		"example.test":     "example.test.",
		"Lower.CASE.test.": "lower.case.test.",
		"*.Test":           "*.test.",
		"ÉxamplE.com":      "Éxample.com.",
		"É.com":            "É.com.",
	} {
		if got := Canonical(s); got != expect {
			t.Errorf("Canonical(%q) = %q, expected %q", s, got, expect)
		}
	}
}
