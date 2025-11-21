package acl

import (
	"context"
	"net"
	"slices"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/infobloxopen/go-trees/iptree"
)

// rule defines ACL policies which will be enforced.
type rule struct {
	policies []policy
}

// policy defines the ACL policy for DNS messages.
// A policy performs the specified action (block/allow) on all DNS messages matched by source IP or QTYPE.
type policy struct {
	action dns.MsgAcceptAction

	// One of these is non-nil and carries the policy
	net *policyNet
	ctx *policyCtx
}

type policyNet struct {
	qtypes []uint16
	filter *iptree.Tree
}

type policyCtx struct {
	ctx    string
	values []string
}

const MsgFilter = dns.MsgAcceptAction(10)

// match matches the DNS message with a list of ACL polices and returns suitable action against the message.
func match(ctx context.Context, policies []policy, w dns.ResponseWriter, r *dns.Msg) dns.MsgAcceptAction {
	for _, policy := range policies {
		switch {
		case policy.net != nil:
			ip := net.ParseIP(dnsutil.RemoteIP(w))
			if ip == nil {
				return dns.MsgIgnore
			}

			_, qtype := dnsutil.Question(r)
			matchAll := len(policy.net.qtypes) == 0
			match := slices.Contains(policy.net.qtypes, qtype)
			if !matchAll && !match {
				continue
			}

			if _, contained := policy.net.filter.GetByIP(ip); !contained {
				println(policy.action)
				continue
			}
			return policy.action
		case policy.ctx != nil:
			value := dnsctx.Ctx(ctx, policy.ctx.ctx)
			if value == nil {
				return dns.MsgAccept
			}
			switch x := value.(type) {
			case bool:
				if x && slices.Contains(policy.ctx.values, "true") {
					return policy.action
				}
				if !x && slices.Contains(policy.ctx.values, "false") {
					return policy.action
				}
			case string:
				if slices.Contains(policy.ctx.values, x) {
					return policy.action
				}
			}
		}
	}
	return dns.MsgAccept
}
