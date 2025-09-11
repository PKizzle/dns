package dbfile

import (
	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/dbfile/zone"
)

// Interface defines the methods for each db* implementation. This is currently unused, and if used
// this needs to live in the pkg/db or something, not tucked away here.
//
// This is the interface dbfile implements on top of the b-tree.
// zone.Zone also implements the following functions:
//
// - New(origin, path string) Interface
type Interface interface {
	Load() error
	Retrieve(*dns.Msg) *dns.Msg
	Get(string) ([]dns.RR, bool)
	Set([]dns.RR) string
	Apex() []dns.RR
	Walk(func(zone.Node) bool)
	AuthoritativeWalk(func(zone.Node, bool) bool)
}

var _ Interface = &zone.Zone{}
