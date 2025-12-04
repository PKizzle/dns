package acl

import (
	"context"
	"io"
	"strconv"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Acl enforces access control policies on DNS queries.
type Acl struct {
	Rules []rule
}

func (a *Acl) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		fam := dnsutil.Family(w)
		if i := ecsContext(ctx); i != nil {
			fam = dnsutil.IPv6Family
			if i.To4() != nil {
				fam = dnsutil.IPv4Family
			}
		}

	Rules:
		for _, rule := range a.Rules {
			action := match(ctx, rule.policies, w, r)
			switch action {
			case dns.MsgAccept:
				break Rules
			case dns.MsgIgnore:
				RequestsDrop.WithLabelValues(dns.Zone(ctx), dnsutil.Network(w), strconv.Itoa(fam)).Inc()
				return
			case dns.MsgReject:
				m := r.Copy()
				dnsutil.SetReply(m, r)
				m.Data = r.Data
				m.Rcode = dns.RcodeRefused
				m.Pseudo = []dns.RR{&dns.EDE{InfoCode: dns.ExtendedErrorBlocked}}

				m.Pack()
				io.Copy(w, m)

				RequestsBlock.WithLabelValues(dns.Zone(ctx), dnsutil.Network(w), strconv.Itoa(fam)).Inc()
				return
			case MsgFilter:
				m := r.Copy()
				dnsutil.SetReply(m, r)
				m.Data = r.Data
				m.Rcode = dns.RcodeRefused
				m.Pseudo = []dns.RR{&dns.EDE{InfoCode: dns.ExtendedErrorFiltered}}

				m.Pack()
				io.Copy(w, m)

				RequestsFilter.WithLabelValues(dns.Zone(ctx), dnsutil.Network(w), strconv.Itoa(fam)).Inc()
				return
			}
		}

		RequestsAllow.WithLabelValues(dns.Zone(ctx), dnsutil.Network(w), strconv.Itoa(fam)).Inc()
		next.ServeDNS(ctx, w, r)
	})
}
