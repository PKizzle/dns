package cookie

import (
	"fmt"
	"strings"

	"codeberg.org/miekg/dns/cmd/testserv/internal/dnsserver"
)

func (c *Cookie) Setup(co dnsserver.Controller) error {
	for co.Next() {
		args := co.RemainingArgs()
		if len(args) == 0 {
			return c.Err(co.PropErr(fmt.Errorf("need a secret")))
		}
		c.Secret = strings.Join(args, " ")
	}
	return nil
}
