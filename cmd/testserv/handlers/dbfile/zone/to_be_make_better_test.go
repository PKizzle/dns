package zone

import (
	"fmt"
	"testing"

	"codeberg.org/miekg/dns"
)

func TestZoneLoad(t *testing.T) {
	z, err := Load("example.org.", "testdata/db.example.org")
	if err != nil {
		t.Fatal(err)
	}
	z.Tree.Scan(func(rrs []dns.RR) bool {
		for i := range rrs {
			fmt.Printf("%s\n", rrs[i])
		}
		return true
	})

	// z.Get("a.b.www.example.org")
}
