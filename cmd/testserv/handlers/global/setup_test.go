package global

import (
	"testing"

	"codeberg.org/miekg/dns/cmd/testserv/internal/conffile"
)

func TestSetup(t *testing.T) {
	testcases := []struct {
		input string
		exp   *Global
	}{
		{`root /tmp`, &Global{Root: "/tmp"}},
		{`root /tmp
		  debug`, &Global{Root: "/tmp"}},
		{`metrics /10 localhost`, &Global{MetricsN: 10}},
	}
	for i, tc := range testcases {
		global := new(Global)
		d := conffile.NewTestDispenser(tc.input)
		err := global.Setup(d)
		if err != nil {
			t.Fatal(err)
		}

		if tc.exp.Root != global.Root {
			t.Errorf("test %d: expected %s, got %s", i, tc.exp.Root, global.Root)
		}
		if tc.exp.MetricsN != global.MetricsN {
			t.Errorf("test %d: expected %d, got %d", i, tc.exp.MetricsN, global.MetricsN)
		}
	}
}
