package acl

import (
	"net"
	"strings"

	"github.com/miekg/sndns/request"
	"go.science.ru.nl/log"

	"github.com/infobloxopen/go-trees/iptree"
	"github.com/miekg/dns"
)

// rule defines a list of Zones and some ACL policies which will be
// enforced on them.
type rule struct {
	zones    []string
	policies []policy
}

// action defines the action against queries.
type action int

// policy defines the ACL policy for DNS queries.
// A policy performs the specified action (block/allow) on all DNS queries
// matched by source IP or QTYPE.
type policy struct {
	action action
	qtypes map[uint16]struct{}
	filter *iptree.Tree
}

const (
	// actionNone does nothing on the queries.
	actionNone = iota
	// actionAllow allows authorized queries to recurse.
	actionAllow
	// actionBlock blocks unauthorized queries towards protected DNS zones.
	actionBlock
	// actionFilter returns empty sets for queries towards protected DNS zones.
	actionFilter
	// actionDrop does not respond for queries towards the protected DNS zones.
	actionDrop
)

// matchWithPolicies matches the DNS query with a list of ACL polices and returns suitable
// action against the query.
func matchWithPolicies(policies []policy, w dns.ResponseWriter, r *dns.Msg) action {
	state := request.Request{W: w, Req: r}

	var ip net.IP
	if idx := strings.IndexByte(state.IP(), '%'); idx >= 0 {
		ip = net.ParseIP(state.IP()[:idx])
	} else {
		ip = net.ParseIP(state.IP())
	}

	// if the parsing did not return a proper response then we simply return 'actionBlock' to
	// block the query
	if ip == nil {
		log.Errorf("Blocking request. Unable to parse source address: %v", state.IP())
		return actionBlock
	}
	qtype := state.QType()
	for _, policy := range policies {
		// dns.TypeNone matches all query types.
		_, matchAll := policy.qtypes[dns.TypeNone]
		_, match := policy.qtypes[qtype]
		if !matchAll && !match {
			continue
		}

		_, contained := policy.filter.GetByIP(ip)
		if !contained {
			continue
		}

		// matched.
		return policy.action
	}
	return actionNone
}
