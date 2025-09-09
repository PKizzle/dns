package dbfile

import (
	"testing"
	"time"

	"codeberg.org/miekg/dns/cmd/testserv/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	testcases := []struct {
		input string
		exp   *Dbfile
	}{
		{`file db.example {
			reload 10s
		}`, &Dbfile{Path: "db.example", Reload: time.Second * 10}},
	}
	for i, tc := range testcases {
		dbfile := new(Dbfile)
		co := dnsserver.NewTestController(tc.input)
		err := dbfile.Setup(co)
		if err != nil {
			t.Fatal(err)
		}

		if tc.exp.Path != dbfile.Path {
			t.Errorf("test %d: expected %s, got %s", i, tc.exp.Path, dbfile.Path)
		}
		if tc.exp.Reload != dbfile.Reload {
			t.Errorf("test %d: expected %s, got %s", i, tc.exp.Reload, dbfile.Reload)
		}
	}
}
