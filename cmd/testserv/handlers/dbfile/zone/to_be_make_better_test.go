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
	z.Walk(func(rrs []dns.RR) bool {
		for i := range rrs {
			fmt.Printf("%s\n", rrs[i])
		}
		return true
	})
	println("=======")
	z.AuthoritativeWalk(func(rrs []dns.RR, auth bool) bool {
		for i := range rrs {
			if auth {
				fmt.Print("AUTH: ")
			} else {
				fmt.Print("NONE: ")
			}
			fmt.Printf("%s\n", rrs[i])
		}
		fmt.Println("*****")
		return true
	})
}
