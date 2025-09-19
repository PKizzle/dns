package template

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sync"
	"text/template"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

type Template struct {
	Path   string
	Regexp *regexp.Regexp
	Types  []uint16
}

// TODO(miek): keep in toplevel?
var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

func (t *Template) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		if len(t.Types) > 0 && !slices.Contains(t.Types, dns.RRToType(r.Question[0])) {
			next.ServeDNS(ctx, w, r)
			return
		}

		if !t.Regexp.MatchString(r.Question[0].Header().Name) {
			next.ServeDNS(ctx, w, r)
			return
		}
		tmpl, err := template.ParseFiles(t.Path)
		if err != nil {
			log.Warn(fmt.Sprintf("failed to find and parse: %s", t.Path))
			next.ServeDNS(ctx, w, r) // call next so we hit the refused at some point
			return
		}

		data := new(Data)
		data.Zone = dns.Zone(ctx)
		data.ID = r.ID
		data.Name = r.Question[0].Header().Name
		data.Question = r.Question[0]
		data.Class = dns.ClassToString[r.Question[0].Header().Class]
		data.Type = dns.TypeToString[dns.RRToType(r.Question[0])]
		data.Msg = r
		data.ResponseWriter = ResponseWriter{
			Family:     dnsutil.Family(w),
			LocalIP:    dnsutil.LocalIP(w),
			LocalPort:  dnsutil.LocalPort(w),
			Network:    dnsutil.Network(w),
			RemoteIP:   dnsutil.RemoteIP(w),
			RemotePort: dnsutil.RemotePort(w),
		}

		buf := bufPool.Get().(*bytes.Buffer)
		err = tmpl.Execute(buf, data)
		if err != nil {
			bufPool.Put(buf)
			log.Warn(fmt.Sprintf("failed to execute template: %s", err))
			next.ServeDNS(ctx, w, r)
			return
		}

		m, err := dnsutil.StringToMsg(buf.String())
		bufPool.Put(buf)
		if err != nil {
			dnsutil.SetReply(m, r)
			m.Rcode = dns.RcodeServerFailure
		}

		m.Data = r.Data

		m.Pack()
		io.Copy(w, m)
	})
}
