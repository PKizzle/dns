package yes

import (
	"slices"
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	testcases := []struct {
		input string
		exp   *Yes
	}{
		{`yes {
				caa aaa
				caa bb
			}
		}`, &Yes{Caa: []string{"aaa", "bb"}}},
	}
	for i, tc := range testcases {
		yes := new(Yes)
		co := dnsserver.NewTestController(tc.input)
		err := yes.Setup(co)
		if err != nil {
			t.Error(err)
			continue
		}

		if slices.Compare(tc.exp.Caa, yes.Caa) != 0 {
			t.Errorf("test %d: expected %v, got %v", i, tc.exp.Caa, yes.Caa)
		}
	}
}
