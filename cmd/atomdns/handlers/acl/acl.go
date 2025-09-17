package acl

import (
	"context"

	"github.com/miekg/sndns/plugin"
	"github.com/miekg/sndns/plugin/metrics"

	"github.com/miekg/dns"
)

// Acl enforces access control policies on DNS queries.
type Acl struct {
	Rules []rule
}

func (a *Acl) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {

	Rules:
		for _, rule := range a.Rules {
			// check zone.
			zone := plugin.Zones(rule.zones).Matches(state.Name())
			if zone == "" {
				continue
			}

			action := matchWithPolicies(rule.policies, w, r)
			switch action {
			case actionDrop:
				RequestDropCount.WithLabelValues(metrics.WithServer(ctx), zone).Inc()
				return dns.RcodeSuccess, nil

			case actionBlock:

				m := new(dns.Msg).
					SetRcode(r, dns.RcodeRefused).
					SetEdns0(4096, true)
				ede := dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeBlocked}
				m.IsEdns0().Option = append(m.IsEdns0().Option, &ede)
				w.WriteMsg(m)
				RequestBlockCount.WithLabelValues(metrics.WithServer(ctx), zone).Inc()
				return dns.RcodeSuccess, nil

			case actionAllow:
				break Rules
			case actionFilter:
				{
					m := new(dns.Msg).
						SetRcode(r, dns.RcodeSuccess).
						SetEdns0(4096, true)
					ede := dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeFiltered}
					m.IsEdns0().Option = append(m.IsEdns0().Option, &ede)
					w.WriteMsg(m)
					RequestFilterCount.WithLabelValues(metrics.WithServer(ctx), zone).Inc()
					return dns.RcodeSuccess, nil
				}
			}
		}

		RequestAllowCount.WithLabelValues(metrics.WithServer(ctx)).Inc()
		next.ServeDNS(ctx, w, r)
	})
}
