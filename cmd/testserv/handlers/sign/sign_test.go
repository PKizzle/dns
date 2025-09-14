package sign

import (
	"testing"

	"codeberg.org/miekg/dns/cmd/testserv/handlers/dbfile/zone"
	"codeberg.org/miekg/dns/cmd/testserv/internal/dnsserver"
)

func TestSign(t *testing.T) {
	// TODO(miek): turn into better test
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
	s.Zones = map[string]*zone.Zone{dnszone: zone.New(dnszone, s.Path)}

	if _, err := s.Sign(dnszone); err != nil {
		t.Fatal(err)
	}
}
