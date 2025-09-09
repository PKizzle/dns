package chaos

import (
	"slices"
	"testing"

	"codeberg.org/miekg/dns/cmd/testserv/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	testcases := []struct {
		input string
		exp   *Chaos
	}{
		{`chaos bla`, &Chaos{Version: "bla"}},
		{`chaos {
			authors {
				aaa
			}
		}`, &Chaos{Version: "", Authors: []string{"aaa"}}},
		{`chaos {
			authors {
			}
		}`, &Chaos{Version: "", Authors: []string{}}},
	}
	for i, tc := range testcases {
		chaos := new(Chaos)
		co := dnsserver.NewTestController(tc.input)
		err := chaos.Setup(co)
		if err != nil {
			t.Fatal(err)
		}

		if tc.exp.Version != chaos.Version {
			t.Errorf("test %d: expected %s, got %s", i, tc.exp.Version, chaos.Version)
		}
		if slices.Compare(tc.exp.Authors, chaos.Authors) != 0 {
			t.Errorf("test %d: expected %v, got %v", i, tc.exp.Authors, chaos.Authors)
		}
	}
}
