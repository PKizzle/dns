package dbfile

import (
	"codeberg.org/miekg/dns/cmd/testserv/internal/dnsserver"
)

// Setup transfer handles the transfer options.
func (d *Dbfile) SetupTransfer(co dnsserver.Controller) error {
	for co.NextBlock() {
		switch co.Val() {
		case "from":

		case "to":

		default:
			return co.SyntaxErr("expected 'to' or 'from', got: " + co.Val())
		}
	}
	return nil
}
