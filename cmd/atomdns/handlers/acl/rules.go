package acl

import (
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

// action defines the action against messages.
type action int

// policy defines the ACL policy for DNS messages.
// A policy performs the specified action (block/allow) on all DNS messages
// matched by source IP or QTYPE.
type policy struct {
	action action
	qtypes []uint16
	filter *iptree.Tree
}

const (
	// actionNone does nothing on the messages.
	actionNone = iota
	// actionAllow allows authorized messages.
	actionAllow
	// actionBlock blocks unauthorized messages towards protected DNS zones.
	actionBlock
	// actionFilter returns empty sets for messages towards protected DNS zones.
	actionFilter
	// actionDrop does not respond for messages towards the protected DNS zones.
	actionDrop
)

// match matches the DNS message with a list of ACL polices and returns suitable action against the message.
func match(policies []policy, w dns.ResponseWriter, r *dns.Msg) action {
	remote := dnsutil.RemoteIP(w)
	ip := net.ParseIP(remote)
	if idx := strings.IndexByte(remote, '%'); idx >= 0 {
		ip = net.ParseIP(remote[:idx])
	}

	if ip == nil {
		return actionDrop
	}
	_, qtype := dnsutil.Question(r)
	for _, policy := range policies {
		matchAll := len(policy.qtypes) == 0
		match := slices.Contains(policy.qtypes, qtype)
		if !matchAll && !match {
			continue
		}

		if _, contained := policy.filter.GetByIP(ip); !contained {
			continue
		}

		return policy.action
	}
	return actionNone
}
