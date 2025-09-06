package nsid

import (
	"context"

	"codeberg.org/miekg/dns"
)

type Nsid struct {
	Data string
}

func (N *Nsid) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	})
}

/*
func (n Nsid) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if option := r.IsEdns0(); option != nil {
		for _, o := range option.Option {
			if _, ok := o.(*dns.EDNS0_NSID); ok {
				nw := &ResponseWriter{ResponseWriter: w, Data: n.Data, request: r}
				return plugin.NextOrFailure(n.Name(), n.Next, ctx, nw, r)
			}
		}
	}
}
*/

/*
// WriteMsg implements the dns.ResponseWriter interface.
func (w *ResponseWriter) WriteMsg(res *dns.Msg) error {
	if w.request.IsEdns0() != nil && res.IsEdns0() == nil {
		res.SetEdns0(w.request.IsEdns0().UDPSize(), true)
	}

	if option := res.IsEdns0(); option != nil {
		var exists bool

		for _, o := range option.Option {
			if e, ok := o.(*dns.EDNS0_NSID); ok {
				e.Code = dns.EDNS0NSID
				e.Nsid = hex.EncodeToString([]byte(w.Data))
				exists = true
			}
		}

		// Append the NSID if it doesn't exist in EDNS0 options
		if !exists {
			option.Option = append(option.Option, &dns.EDNS0_NSID{
				Code: dns.EDNS0NSID,
				Nsid: hex.EncodeToString([]byte(w.Data)),
			})
		}
	}

	return w.ResponseWriter.WriteMsg(res)
}
*/
