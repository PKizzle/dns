package yes

import (
	"strings"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func (y *Yes) Setup(co *dnsserver.Controller) error {
	if co.Next() {
		for co.NextBlock(0) {
			if co.Val() != "caa" {
				return co.PropErr()
			}
			args := co.RemainingArgs()
			if len(args) == 0 {
				return co.ArgErr()
			}
			y.Caa = append(y.Caa, strings.TrimSpace(args[0]))
		}
	}
	return nil
}
