package zone

import (
	"fmt"
	"testing"
)

func testZoneLoad(t *testing.T) {
	z := New("example.org.", "testdata/db.example.org")
	if err := z.Load(); err != nil {
		t.Fatal(err)
	}
	z.Walk(func(n Node) bool {
		fmt.Printf("%s :", n.Name)
		for i := range n.RRs {
			fmt.Printf("%s\n", n.RRs[i])
		}
		return true
	})
	println("=======")
	z.AuthoritativeWalk(func(n Node, auth bool) bool {
		fmt.Printf("%s :", n.Name)
		for i := range n.RRs {
			if auth {
				fmt.Print("AUTH: ")
			} else {
				fmt.Print("NONE: ")
			}
			fmt.Printf("%s\n", n.RRs[i])
		}
		fmt.Println("*****")
		return true
	})
}
