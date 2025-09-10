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
	Get(*dns.Msg) *dns.Msg
	//	Set([]dns.RR) ([]dns.RR, bool)  - TODO(miek): implement for zone.Zone
	Apex() []dns.RR
	Walk(func([]dns.RR) bool)
	AuthoritativeWalk(func([]dns.RR, bool) bool)
}

var _ Interface = &zone.Zone{}
