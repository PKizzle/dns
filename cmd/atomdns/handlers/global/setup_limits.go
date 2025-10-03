package global

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/conffile"
)

type Limits struct {
	MaxTCPQueries int
	Servers       int
}

func (g *Global) SetupLimits(d *conffile.Dispenser) (Limits, error) {
	l := Limits{MaxTCPQueries: 128, Servers: -1}
	for d.NextBlock(1) {
		switch d.Val() {
		case "tcp":
			limits := d.RemainingArgs()
			if len(limits) != 1 {
				return l, d.PropErr(fmt.Errorf("need single limit"))
			}
			n, err := strconv.Atoi(limits[0])
			if err != nil || n < -1 {
				return l, d.PropErr(fmt.Errorf("not a number: %q", limits[0]))
			}
			l.MaxTCPQueries = n
		case "run":
			exprs := d.RemainingArgs()
			if len(exprs) != 1 {
				return l, d.PropErr(fmt.Errorf("need single expression"))
			}
			if strings.HasPrefix(strings.ToLower(exprs[0]), "numcpu()*") {
				n, err := strconv.Atoi(exprs[0][len("numcpu()*"):])
				if err != nil || n < 0 {
					return l, d.PropErr(fmt.Errorf("not a (positive) number: %q", exprs[0]))
				}
				g.Servers = runtime.NumCPU() * n
			} else {
				n, err := strconv.Atoi(exprs[0])
				if err != nil || n < 0 {
					return l, d.PropErr(fmt.Errorf("not a (positive) number: %q", exprs[0]))
				}
				l.Servers = n
			}
		default:
			return l, d.ArgErr()
		}
	}
	return l, nil
}
