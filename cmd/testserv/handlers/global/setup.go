package global

import "codeberg.org/miekg/dns/cmd/testserv/conffile"

func (g *Global) Setup(d conffile.Dispenser) error {
	if d.Next() {
		switch d.Val() {
		case "root":
			if !d.NextArg() {
				g.Err(d.PropErr())
			}
			g.Root = d.Val()
		}
	}
	return nil
}
