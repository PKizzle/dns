package dbfile

import (
	"fmt"
	"time"

	"codeberg.org/miekg/dns/cmd/testserv/internal/dnsserver"
)

func (d *Dbfile) Setup(co dnsserver.Controller) error {
	if co.Next() {
		args := co.RemainingArgs()
		if len(args) != 1 {
			return d.Err(co.ArgErr())
		}
		d.Path = args[0]
		for co.NextBlock() {
			switch co.Val() {
			case "reload":
				co.Next()
				dur, err := time.ParseDuration(co.Val())
				if err != nil {
					d.Err(co.PropErr(err))
				}
				if dur < time.Second*10 {
					return d.Err(co.PropErr(fmt.Errorf("reload duration must be > 10s")))
				}
				d.Reload = dur
			case "no-minimal":
				d.NoMinimal = true
			default:
				return d.Err(co.PropErr())
			}
		}
	}
	return nil
}
