package log

import (
	"slices"
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	testcases := []struct {
		input string
		exp   *Log
	}{
		{`log {
			aaa/addr
			bbb/addr
		}`, &Log{Contexts: []string{"aaa/addr", "bbb/addr"}}},
	}
	for i, tc := range testcases {
		log := new(Log)
		co := dnsserver.NewTestController(tc.input)
		err := log.Setup(co)
		if err != nil {
			t.Fatal(err)
		}

		if slices.Compare(tc.exp.Contexts, log.Contexts) != 0 {
			t.Errorf("test %d: expected %v, got %v", i, tc.exp.Contexts, log.Contexts)
		}
	}
}
