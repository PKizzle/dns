package sign

import (
	"fmt"
	"testing"

	"codeberg.org/miekg/dns/cmd/testserv/handlers/dbfile/zone"
)

func TestWalkNSEC(*testing.T) {
	z := zone.New("miek.nl.", "testdata/db.miek.nl")
	z.Load()

	pair, _ := keypair("./testdata/Kmiek.nl.+013+59725")
	nf := &nsecfn{zone: z, keypairs: []KeyPair{pair}, ttl: 3600}
	z.AuthoritativeWalk(nf.Walk)
	// we need to insert the last nsec
	for i := range nf.nsecs {
		z.Set(nf.nsecs[i])
	}
	z.Set(nf.Last(z.Origin))

	z.Walk(func(n zone.Node) bool {
		fmt.Println(n)
		return true
	})
}
