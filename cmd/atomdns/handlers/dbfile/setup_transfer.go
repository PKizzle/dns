package dbfile

import (
	"fmt"
	"net"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"codeberg.org/miekg/dns/dnsutil"
)

// Setup transfer handles the transfer options.
func (d *Dbfile) SetupTransfer(co *dnsserver.Controller) error {
	for co.NextBlock(1) {
		switch co.Val() {
		case "}":
			break
		case "from":
			args := co.RemainingArgs()
			if err := parseIPs(args); err != nil {
				return co.PropErr(err)
			}
			if len(args) == 0 {
				return co.ArgErr()
			}
			d.From.IPs = args

			for co.NextBlock(2) {
				switch co.Val() {
				case "key":
					if err := d.From.SetupTransferTSIG(co); err != nil {
						return err
					}
				}
			}

		case "to":
			args := co.RemainingArgs()
			if err := parseIPs(args); err != nil {
				return co.PropErr(err)
			}
			d.To.IPs = args

			for co.NextBlock(2) {
				switch co.Val() {
				case "key":
					if err := d.To.SetupTransferTSIG(co); err != nil {
						return err
					}
				case "notify":
					args := co.RemainingArgs()
					if len(args) == 0 {
						return co.ArgErr()
					}
					if err := parseIPs(args); err != nil {
						return co.PropErr(err)
					}
					d.To.Notifies = args
				case "source":
					args = co.RemainingArgs()
					if len(args) == 0 {
						return co.ArgErr()
					}
					if err := parseIPs(args); err != nil {
						return co.PropErr(err)
					}
					d.To.Sources = args
				}
			}
			if len(d.To.IPs) == 0 && len(d.To.Notifies) == 0 {
				return co.Err("both 'to' and 'notify' are empty")
			}

		default:
			return co.SyntaxErr("expected 'to' or 'from', got: " + co.Val())
		}
	}
	return nil
}

func parseIPs(args []string) error {
	for _, arg := range args {
		if ip := net.ParseIP(arg); ip == nil {
			return fmt.Errorf("failed to parse IP %q", arg)
		}
	}
	return nil
}

// SetuptransferTSIG handles the transfer tsig option.
func (t *Transfer) SetupTransferTSIG(co *dnsserver.Controller) error {
	// we're called after key ....
	args := co.RemainingArgs()
	if len(args) != 3 {
		return co.ArgErr()
	}
	if !dnsutil.IsName(args[0]) {
		return co.PropErr(fmt.Errorf("name %q is not a domain name", args[0]))
	}
	if !dnsutil.IsName(args[1]) {
		return co.PropErr(fmt.Errorf("algorithm %s is not a domain name", args[0]))
	}
	t.TSIG = dns.NewTSIG(dnsutil.Canonical(args[0]), dnsutil.Canonical(args[1]), 0)
	t.TSIGSecret = args[2]
	return nil
}
