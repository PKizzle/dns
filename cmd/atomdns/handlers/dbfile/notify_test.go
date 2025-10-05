package dbfile

import "testing"

func TestDbFileNotifySource(t *testing.T) {
	testcases := []struct {
		to      string
		sources []string
		exp     string
	}{
		{
			"176.58.119.54",
			[]string{"176.58.119.54", "2a01:7e00::f03c:91ff:fe79:234c"},
			"176.58.119.54",
		},
		{
			"::1",
			[]string{"176.58.119.54", "2a01:7e00::f03c:91ff:fe79:234c"},
			"2a01:7e00::f03c:91ff:fe79:234c",
		},
		{
			"::1",
			[]string{"176.58.119.54"},
			"",
		},
	}

	for i, tc := range testcases {
		got := source(tc.to, tc.sources)
		if got == nil && tc.exp == "" {
			continue
		}
		if got.String() != tc.exp {
			t.Errorf("test %d, expected %s, got %s", i, tc.exp, got.String())
		}
	}
}
