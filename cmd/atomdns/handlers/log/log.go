package log

import (
	"bytes"
	"context"
	"log/slog"
	"strconv"
	"sync"
	"text/template"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

type Log int

var logger = slog.Default()

func (l *Log) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		b := bufPool.Get().(*bytes.Buffer)

		logtmpl.Execute(b, logWrap{w, r})
		logger.Info(b.String())

		b.Reset()
		bufPool.Put(b)
		next.ServeDNS(ctx, w, r)
	})
}

type logWrap struct {
	dns.ResponseWriter
	*dns.Msg
}

var funcmap = template.FuncMap{
	"id":     func(l logWrap) string { return strconv.Itoa(int(l.Msg.ID)) },
	"opcode": func(l logWrap) string { return dnsutil.OpcodeToString(l.Msg.Opcode) },
	"bufsize": func(l logWrap) string {
		if l.Msg.UDPSize < 512 {
			return "512"
		}
		return strconv.Itoa(int(l.Msg.UDPSize))
	},
	"flags": func(l logWrap) string { return flags(l) },
	"size":  func(l logWrap) string { return strconv.Itoa(len(l.Msg.Data)) },
	"type": func(l logWrap) string {
		_, t := dnsutil.Question(l.Msg)
		return dnsutil.TypeToString(t)
	},
	"name":    func(l logWrap) string { z, _ := dnsutil.Question(l.Msg); return z },
	"class":   func(l logWrap) string { return dnsutil.ClassToString(l.Msg.Question[0].Header().Class) },
	"network": func(l logWrap) string { return dnsutil.Network(l.ResponseWriter) },
	"remote":  func(l logWrap) string { return dnsutil.RemoteIP(l.ResponseWriter) },
	"port":    func(l logWrap) string { return dnsutil.RemotePort(l.ResponseWriter) },
	"local":   func(l logWrap) string { return dnsutil.LocalIP(l.ResponseWriter) },
}

var logtmpl = template.Must(template.New("logFunc").Funcs(funcmap).Parse(line))

const line = `{{remote .}}:{{port .}} - {{id .}} "{{type .}} {{class .}} {{name .}} {{network .}} {{size .}} {{bufsize .}}" {{flags .}} {{opcode .}}`

var bufPool = &sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

func flags(l logWrap) string {
	h := l.Msg.MsgHeader
	b := bufPool.Get().(*bytes.Buffer)
	defer func() {
		b.Reset()
		bufPool.Put(b)
	}()
	if h.Response {
		b.WriteString(" qr")
	}
	if h.Authoritative {
		b.WriteString(" aa")
	}
	if h.Truncated {
		b.WriteString(" tc")
	}
	if h.RecursionDesired {
		b.WriteString(" rd")
	}
	if h.RecursionAvailable {
		b.WriteString(" ra")
	}
	if h.Zero {
		b.WriteString(" z")
	}
	if h.AuthenticatedData {
		b.WriteString(" ad")
	}
	if h.CheckingDisabled {
		b.WriteString(" cd")
	}
	if h.Security {
		b.WriteString(" do")
	}
	if h.CompactAnswers {
		b.WriteString(" co")
	}
	if h.Delegation {
		b.WriteString(" de")
	}
	return string(b.Bytes()[1:])
}
