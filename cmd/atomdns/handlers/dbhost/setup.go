package dbhost

import (
	"strconv"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func (d *Dbhost) Setup(co *dnsserver.Controller) error {
	d.Path = "/etc/hosts"
	for co.Next() {
		paths := co.RemainingPaths()
		if len(paths) > 1 {
			return co.ArgErr()
		}
		if len(paths) == 1 {
			d.Path = paths[0]
		}

		if co.NextBlock(0) {
			switch co.Val() {
			case "ttl":
				args := co.RemainingArgs()
				if len(args) == 0 {
					return co.ArgErr()
				}
				ttl, err := strconv.ParseUint(args[0], 10, 32)
				if err != nil {
					return co.PropErr(err)
				}
				d.ttl = uint32(ttl)

			default:
				return co.PropErr()
			}
		}
	}
	return d.Load()
}
