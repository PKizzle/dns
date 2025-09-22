package dbsqlite

import (
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	dbsqlite := new(Dbsqlite)
	dbsqlite.Zone = new(Zone)
	co := dnsserver.NewTestController("")
	dbsqlite.Setup(co)
}
