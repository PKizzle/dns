package zone

import (
	"fmt"
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
)

func testZoneLoad(t *testing.T) {
	z := New("example.", "testdata/db.example")
	if err := z.Load(); err != nil {
		t.Fatal(err)
	}
	z.Walk(func(n dnszone.Node) bool {
		fmt.Printf("%s :", n.Name)
		if len(n.RRs) == 0 {
			fmt.Printf("ENT\n")
			return true
		} else {
			fmt.Printf("RRSET\n")
		}
		for i := range n.RRs {
			fmt.Printf("%s\n", n.RRs[i])
		}
		return true
	})
}
