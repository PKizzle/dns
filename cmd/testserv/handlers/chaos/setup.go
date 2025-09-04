package chaos

import (
	"codeberg.org/miekg/dns/cmd/testserv/conffile"
)

func (c *Chaos) Setup(d conffile.Dispenser) error {
	if d.Next() {
		args := d.RemainingArgs()
		if len(args) > 1 {
			return d.ArgErr()
		}
		authors := []string{}
		for d.NextBlock() {
			switch d.Val() {
			case "authors":
				for d.Next() {
					if d.Val() == "}" {
						break
					}
					if d.Val() == "{" {
						continue
					}
					authors = append(authors, d.Val())
				}

			default:
				return d.ArgErr()
			}
		}
		if len(authors) > 0 {
			c.Authors = authors
		}

	}
	return nil
}
