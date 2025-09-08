package chaos

import "codeberg.org/miekg/dns/cmd/testserv/internal/dnsserver"

func (c *Chaos) Setup(co dnsserver.Controller) error {
	if co.Next() {
		args := co.RemainingArgs()
		if len(args) > 1 {
			return co.ArgErr()
		}
		authors := []string{}
		for co.NextBlock() {
			switch co.Val() {
			case "authors":
				for co.Next() {
					if co.Val() == "}" {
						break
					}
					if co.Val() == "{" {
						continue
					}
					authors = append(authors, co.Val())
				}

			default:
				return co.PropErr()
			}
		}
		if len(authors) > 0 {
			c.Authors = authors
		}
	}
	return nil
}
