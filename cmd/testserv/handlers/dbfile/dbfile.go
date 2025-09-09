package dbfile

import (
	"context"
	"time"

	"codeberg.org/miekg/dns"
)

// Interface defines the methods for each db* implementation. This is currently unused, and if used
// this needs to live in the pkg/db or something, not tucked away here.
//
// This is the interface dbfile implements on top of the b-tree.
type Interface interface {
	New(origin, path string) Interface
	Load(origin, path string) Interface
	Set([]dns.RR) ([]dns.RR, bool)
	Get([]dns.RR) ([]dns.RR, bool)
	Walk(func([]dns.RR) bool)
	AuthoritativeWalk(func([]dns.RR, bool) bool)
}

type Dbfile struct {
	Path           string
	Reload         time.Duration
	DisableMinimal bool
}

func (d *Dbfile) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		// do the lookup
	})
}
