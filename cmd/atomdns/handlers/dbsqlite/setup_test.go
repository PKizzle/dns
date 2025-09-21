package dbsqlite

import (
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	dbsqlite := new(Dbsqlite)
	co := dnsserver.NewTestController("")
	dbsqlite.Setup(co)
}
