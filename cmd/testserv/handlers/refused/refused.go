package refused

import (
	"context"
	"io"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Refused is a handler that returns refused, it use is to be the final handler, that is reached, returns
// refused.
type Refused int

func (r *Refused) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := &dns.Msg{Data: r.Data}
		dnsutil.SetReply(m, r)
		m.Rcode = dns.RcodeRefused
		m.Pack()
		io.Copy(w, m)
	})
}
