package acl

import (
	"net"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"github.com/infobloxopen/go-trees/iptree"
)

const (
	nettype = iota
	contextype
)

func (a *Acl) Setup(co *dnsserver.Controller) error {
	for co.Next() {
		r := rule{}
		for co.NextBlock(0) {
			p := policy{}

			switch co.Val() {
			case "allow":
				p.action = dns.MsgAccept
			case "block":
				p.action = dns.MsgReject
			case "filter":
				p.action = MsgFilter
			case "drop":
				p.action = dns.MsgIgnore
			default:
				return co.Errf("unexpected token %q, expected 'allow', 'block', 'filter' or 'drop'", co.Val())
			}
			args := co.RemainingArgs()
			if len(args) == 0 {
				p.net = &policyNet{filter: iptree.NewTree()}
				_, IPv4All, _ := net.ParseCIDR("0.0.0.0/0")
				_, IPv6All, _ := net.ParseCIDR("::/0")
				p.net.filter.InplaceInsertNet(IPv4All, struct{}{})
				p.net.filter.InplaceInsertNet(IPv6All, struct{}{})
				r.policies = append(r.policies, p)
				continue
			}

			tp := contextype
			if _, _, err := net.ParseCIDR(normalize(args[0])); err == nil { // == nil
				tp = nettype
				p.net = &policyNet{filter: iptree.NewTree()}
			}
			for i, arg := range args {
				switch tp {
				case contextype:
					if i == 0 {
						p.ctx = new(policyCtx)
						p.ctx.ctx = arg
					} else {
						p.ctx.values = append(p.ctx.values, arg)
					}
				case nettype:
					qtype := dns.StringToType[arg]
					if qtype != 0 {
						p.net.qtypes = append(p.net.qtypes, qtype)
					} else {
						_, source, err := net.ParseCIDR(normalize(arg))
						if err != nil {
							co.Errf("illegal CIDR notation %q", normalize(arg))
						}
						p.net.filter.InplaceInsertNet(source, struct{}{})
					}
				}
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
