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
				source ::1
			}
		}`, &Yes{Caa: []string{"aaa", "bb"}, Sources: []string{"::1"}}},
		{`yes {
				caa aaa
				source 127.0.0.1
			}
		}`, &Yes{Caa: []string{"aaa"}, Sources: []string{"127.0.0.1"}}},
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
		if slices.Compare(tc.exp.Sources, yes.Sources) != 0 {
			t.Errorf("test %d: expected %v, got %v", i, tc.exp.Sources, yes.Sources)
		}
	}
}
