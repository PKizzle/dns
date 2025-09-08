package metrics

import (
	"testing"

	"codeberg.org/miekg/dns/cmd/testserv/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	testcases := []struct {
		input    string
		expN     uint64
		disabled bool
	}{
		{`metrics /11`, 11, false},
		{`metrics /12 enable"`, 12, false},
		{`metrics enable`, 10, false},
		{`metrics disable`, 10, true},
		{`metrics /13 disable`, 13, true},
	}
	for i, tc := range testcases {
		metrics := new(Metrics)
		co := dnsserver.NewTestController(tc.input)
		err := metrics.Setup(co)
		if err != nil {
			t.Fatal(err)
		}

		if tc.expN != metrics.N {
			t.Errorf("test %d: expected N %d, got %d", i, tc.expN, metrics.N)
		}
		if tc.disabled != metrics.disable {
			t.Errorf("test %d: expected %t, got %t", i, tc.disabled, metrics.disable)
		}
	}
}
