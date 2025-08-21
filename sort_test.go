package dns

import "testing"

func TestCompareName(t *testing.T) {
	testcases := []struct {
		a        string
		b        string
		expected int
	}{
		{"www.miek.nl.", "miek.nl.", 1},
	}
	for _, tc := range testcases {
		x := CompareName(tc.a, tc.b)
		if x != tc.expected {
			t.Errorf("expected %d, for %s %s, got %d", tc.expected, tc.a, tc.b, x)
		}
	}
}
