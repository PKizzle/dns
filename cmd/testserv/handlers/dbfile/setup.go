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
			return co.ArgErr()
		}
		d.Path = args[0]
		for co.NextBlock() {
			switch co.Val() {
			case "reload":
				co.NextArg()
				dur, err := time.ParseDuration(co.Val())
				if err != nil {
					return co.PropErr(err)
				}
				if dur < time.Second*10 {
					return co.PropErr(fmt.Errorf("reload duration must be > 10s"))
				}
				d.Reload = dur
			case "minimal":
				co.NextArg()
				if co.Val() != "disable" {
					return co.PropErr(fmt.Errorf("only valid value is %q", "disable"))
				}
				d.DisableMinimal = true
			default:
				return co.PropErr()
			}
		}
	}
	// for all co.Keys() we are now loading the zone in a go-routine, might do co.OnStartup
	// where this is added, so we get a generic - can also copy that from old caddy as well.

	return nil
}
