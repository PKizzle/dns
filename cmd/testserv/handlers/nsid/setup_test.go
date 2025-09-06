package nsid

import (
	"os"
	"testing"

	"codeberg.org/miekg/dns/cmd/testserv/internal/dnsserver"
)

func TestSetupNsid(t *testing.T) {
	defaultNsid, err := os.Hostname()
	if err != nil {
		defaultNsid = "localhost"
	}
	testcases := []struct {
		input string
		exp   string
	}{
		{`nsid`, defaultNsid},
		{`nsid "ps0"`, "ps0"},
	}
	for i, tc := range testcases {
		nsid := new(Nsid)
		co := dnsserver.NewTestController(tc.input)
		err := nsid.Setup(co)

		if tc.exp == "" {
			if err == nil {
				t.Errorf("test %d: expected error, got nothing", i)
			}
			continue
		}

		if tc.exp != nsid.Data {
			t.Errorf("test %d: expected %s, got %s", i, tc.input, nsid.Data)
		}
	}
}
