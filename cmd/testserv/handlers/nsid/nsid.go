package nsid

import (
	"context"
	"encoding/hex"
	"io"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
)

type Nsid struct {
	Data string
}

func (n *Nsid) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		r.Unpack()
		// if we don't find a nsid we just skip the whole thing
		found := false
		for _, o := range r.Pseudo {
			if _, ok := o.(*dns.NSID); ok {
				found = true
				break
			}
		}
		if !found {
			next.ServeDNS(ctx, w, r)
			return
		}

		rw := dnstest.NewRecorder(w)
		next.ServeDNS(ctx, rw, r)
		m := rw.Msg
		o := &dns.NSID{Nsid: hex.EncodeToString([]byte(n.Data))}
		m.Pseudo = append(m.Pseudo, o)
		m.Pack()
		io.Copy(w, m)
	})
}
