package conffile

import "testing"

func TestAddr(t *testing.T) {
	testcases := []struct {
		in  string
		exp string
	}{
		{"37.48.122.141", "37.48.122.141:53"},
		{"37.48.122.141:53", "37.48.122.141:53"},
		{"37.48.122.141:1053", "37.48.122.141:1053"},
		{"[::1]:1053", "[::1]:1053"},
		{"::1", "[::1]:53"},
	}
	for i, tc := range testcases {
		x, err := addr(tc.in)
		if err != nil {
			t.Errorf("test %d, failed: %s", i, err)
		}
		if x != tc.exp {
			t.Errorf("test %d, expected %s, got %s", i, tc.exp, x)
		}
	}
}
