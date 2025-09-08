package metrics

import (
	"fmt"

	"codeberg.org/miekg/dns/cmd/testserv/internal/conffile"
)

func (m *Metrics) Setup(co conffile.Dispenser) error {
	if co.Next() {
		for co.NextBlock() {
			switch co.Val() {
			case "metrics":
				co.Next()
				switch co.Val() {
				case "disable":
					m.disable = true
				case "enable", "":
					// nothing
				default:
					return co.PropErr(fmt.Errorf("only valid value is %q", co.Val()))
				}
			default:
				return co.PropErr()
			}
		}
	}
	return nil
}
