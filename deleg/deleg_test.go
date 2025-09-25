package deleg_test

import (
	"testing"

	"codeberg.org/miekg/dns"
)

func TestDELEG(t *testing.T) {
	// TODO(miek): include more tests, or rename the test.
	testcases := []struct {
		in  string
		exp string
	}{
		{
			"$ORIGIN example.\nexample.   DELEG server-ipv4=192.0.2.1 server-ipv6=2001:DB8::1\n",
			"example. IN 3600  DELEG server-ipv4=192.0.2.1 server-ipv6=2001:DB8::1",
		},
		{
			"$ORIGIN example.\nexample.   DELEG server-name=ns2,ns3.example.org.\n",
			"example. IN 3600  DELEG server-name=ns2.example.,ns3.example.org.",
		},
	}
	for _, tc := range testcases {
		rr, err := dns.New(tc.in)
		if err != nil {
			t.Fatal(err)
		}
		println(rr.String())
	}
}
