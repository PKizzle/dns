package sign

import (
	"fmt"
	"testing"

	"codeberg.org/miekg/dns/cmd/testserv/handlers/dbfile/zone"
)

func TestWalkNSEC(*testing.T) {
	z := zone.New("miek.nl.", "testdata/db.miek.nl")
	z.Load()

	nf := &nsecfn{zone: z}
	z.AuthoritativeWalk(nf.Walk)

	z.Walk(func(n zone.Node) bool {
		fmt.Printf("%+v\n", n)
		return true
	})
}
