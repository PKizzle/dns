package global

import (
	"codeberg.org/miekg/dns/cmd/atomdns/internal/conffile"
)

func (g *Global) SetupTLS(d conffile.Dispenser) error {
	for d.NextBlock(0) {
		switch d.Val() {
		case "cert":
		case "key":
		case "contact":
		default:
			return d.ArgErr()
		}
	}
	return nil

}
