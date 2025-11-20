package acl

import (
	"context"
	"net"
	"slices"
	"strings"

	"codeberg.org/miekg/dns"
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
	*policyNet
	*policyCtx
}

type policyNet struct {
	qtypes []uint16
	filter *iptree.Tree
}

type policyCtx struct {
	ctx   string
	value string
}

const MsgFilter = dns.MsgAcceptAction(10)

// match matches the DNS message with a list of ACL polices and returns suitable action against the message.
func match(ctx context.Context, policies []policy, w dns.ResponseWriter, r *dns.Msg) dns.MsgAcceptAction {
	for _, policy := range policies {
		switch {
		case policy.policyNet != nil:
			remote := dnsutil.RemoteIP(w)
			ip := net.ParseIP(remote)
			if idx := strings.IndexByte(remote, '%'); idx >= 0 {
				ip = net.ParseIP(remote[:idx])
			}

			if ip == nil {
				return dns.MsgIgnore
			}

			_, qtype := dnsutil.Question(r)
			matchAll := len(policy.qtypes) == 0
			match := slices.Contains(policy.qtypes, qtype)
			if !matchAll && !match {
				continue
			}

			if _, contained := policy.filter.GetByIP(ip); !contained {
				continue
			}

			return policy.action
		case policy.policyCtx != nil:
			value := ctx.Value(policy.policyCtx.ctx)
			if value == nil {
				return MsgFilter
			}
		}
	}
	return dns.MsgAccept
}
