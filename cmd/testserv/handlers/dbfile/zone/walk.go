package zone

import (
	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Walk walks the zone and call fn on each element found, as long as f returns true the walk is continued.
// The order of the walk is ascending order: from apex to longest child.
func (z *Zone) Walk(fn func(rrs []dns.RR) bool) { z.Tree.Scan(fn) }

// AuthoritativeWalk walks the the zone, but keeps track of authoritative names and call fn auth a boolean
// indicating is the name is considered that.
func (z *Zone) AuthoritativeWalk(fn func(rrs []dns.RR, auth bool) bool) {
	delegated := map[string]struct{}{}

	z.Walk(func(rrs []dns.RR) bool {
		name := rrs[0].Header().Name
		if len(name) > len(z.Origin) { // apex also has NSes, if we add those the entire zone is delegated
			println(name, z.Origin)
			for _, rr := range rrs {
				if _, ok := rr.(*dns.NS); ok {
					delegated[name] = struct{}{}
					break
				}
			}
		}
		auth := true
		i := 0
		j := 0
		end := false
		for ; !end; j, end = dnsutil.Next(name, i) {
			if len(name[j:]) < len(z.Origin) {
				break
			}
			println("CHECKING: ", name[j:], len(name[j:]), len(z.Origin))
			if _, ok := delegated[name[j:]]; ok {
				auth = false
				break
			}
			i++
		}

		return fn(rrs, auth)
	})
}
