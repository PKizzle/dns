package sign

import (
	"fmt"
	"testing"

	"codeberg.org/miekg/dns/cmd/testserv/handlers/dbfile/zone"
	"codeberg.org/miekg/dns/cmd/testserv/internal/dnsserver"
)

func TestSign(t *testing.T) {
	dnszone := "miek.nl."
	config := `sign testdata/db.miek.nl {
        		key testdata/Kmiek.nl.+013+59725
	    	}`

	s := new(Sign)
	co := dnsserver.NewTestController(config)
	err := s.Setup(co)
	if err != nil {
		t.Fatal(err)
	}
	// because of NewTestController's way of working we miss sign.Zones map, because we don't have keys to add.
	s.Zones = make(map[string]*zone.Zone)
	s.Zones[dnszone] = zone.New(dnszone, s.Path)

	z, err := s.Sign(dnszone)
	if err != nil {
		t.Fatal(err)
	}

	z.Walk(func(n zone.Node) bool {
		fmt.Println(n)
		return true
	})
}
