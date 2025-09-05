package log

import (
	"bytes"
	"context"
	"log"
	"strconv"
	"sync"
	"text/template"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

type Log struct {
	tmpl *template.Template
}

// Log logs some output for each request received
func (l *Log) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		b := bufPool.Get().(*bytes.Buffer)
		l.tmpl.Execute(b, logWrap{w, r})

		log.Print(b.String())

		bufPool.Put(b)
		next.ServeDNS(ctx, w, r)
	})
}

type logWrap struct {
	dns.ResponseWriter
	*dns.Msg
}

var funcmap = template.FuncMap{
	">id":      func(l logWrap) string { return strconv.Itoa(int(l.Msg.ID)) },
	">opcode":  func(l logWrap) string { return dnsutil.OpcodeToString(l.Msg.Opcode) },
	">bufsize": func(l logWrap) string { return strconv.Itoa(int(l.Msg.UDPSize)) },
	">flags":   func(l logWrap) string { return "todo" },
	"size":     func(l logWrap) string { return strconv.Itoa(len(l.Msg.Data)) },
	"type": func(l logWrap) string {
		_, t := dnsutil.Question(l.Msg)
		return dnsutil.TypeToString(t)
	},
	"name":    func(l logWrap) string { z, _ := dnsutil.Question(l.Msg); return z },
	"network": func(l logWrap) string { return dnsutil.Network(l.ResponseWriter) },
	"remote":  func(l logWrap) string { return dnsutil.RemoteIP(l.ResponseWriter) },
	"port":    func(l logWrap) string { return dnsutil.RemotePort(l.ResponseWriter) },
	"local":   func(l logWrap) string { return dnsutil.LocalIP(l.ResponseWriter) },
}

func Template(format string) *template.Template {
	return template.Must(template.New("logFunc").Funcs(funcmap).Parse(format))
}

const Default = `{remote}:{port} - {>id} "{type} {class} {name} {network} {size} {>bufsize}" {>rcode} {>flags} {>opcode}`

var bufPool = &sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}
