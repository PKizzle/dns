package yes

import (
	"strings"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func (y *Yes) Setup(co *dnsserver.Controller) error {
	if co.Next() {
		for co.NextBlock(0) {
			switch co.Val() {
			case "caa":
				args := co.RemainingArgs()
				if len(args) == 0 {
					return co.ArgErr()
				}
				y.Caa = append(y.Caa, strings.TrimSpace(args[0]))
			case "source":
				args, err := co.RemainingIPs()
				if err != nil {
					return co.PropErr(err)
				}
				if len(args) == 0 {
					return co.ArgErr()
				}
				y.Sources = append(y.Sources, args...)
			default:
				return co.PropErr()
			}
		}
	}
	if len(y.Caa) == 0 {
		return co.ArgErr()
	}
	if len(y.Sources) == 0 {
		return co.ArgErr()
	}
	return nil
}
