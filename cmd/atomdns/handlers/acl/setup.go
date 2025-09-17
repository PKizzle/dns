package acl

import (
	"net"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"github.com/infobloxopen/go-trees/iptree"
)

func (a *Acl) Setup(co *dnsserver.Controller) error {
	for co.Next() {
		r := rule{}
		for co.NextBlock(0) {
			p := policy{}

			switch co.Val() {
			case "allow":
				p.action = actionAllow
			case "block":
				p.action = actionBlock
			case "filter":
				p.action = actionFilter
			case "drop":
				p.action = actionDrop
			default:
				return co.Errf("unexpected token %q, expected 'allow', 'block', 'filter' or 'drop'", co.Val())
			}

			p.qtypes = []uint16{}
			p.filter = iptree.NewTree()

			hasNet := false

			args := co.RemainingArgs()
			if len(args) == 0 {
				return co.ArgErr()
			}

			for _, a := range args {
				// either DNS types or IP addresses, there is no overlap between the two
				qtype := dns.StringToType[a]
				switch qtype {
				case 0:
					hasNet = true
					_, source, err := net.ParseCIDR(normalize(a))
					if err != nil {
						return co.Errf("illegal CIDR notation %q", normalize(a))
					}
					p.filter.InplaceInsertNet(source, struct{}{})
				default:
					p.qtypes = append(p.qtypes, qtype)
				}
			}

			if !hasNet {
				_, IPv4All, _ := net.ParseCIDR("0.0.0.0/0")
				_, IPv6All, _ := net.ParseCIDR("::/0")
				p.filter.InplaceInsertNet(IPv4All, struct{}{})
				p.filter.InplaceInsertNet(IPv6All, struct{}{})
			}

			r.policies = append(r.policies, p)
		}
		a.Rules = append(a.Rules, r)
	}
	return nil
}

// normalize appends '/32' for any single IPv4 address and '/128' for IPv6.
func normalize(rawNet string) string {
	if idx := strings.IndexAny(rawNet, "/"); idx >= 0 {
		return rawNet
	}

	if idx := strings.IndexAny(rawNet, ":"); idx >= 0 {
		return rawNet + "/128"
	}
	return rawNet + "/32"
}
