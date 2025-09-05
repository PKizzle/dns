package log

import (
	"bytes"
	"context"
	"log"
	"strconv"
	"strings"
	"sync"
	"text/template"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

type Log int

func (l *Log) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		b := bufPool.Get().(*bytes.Buffer)

		logtmpl.Execute(b, logWrap{w, r})
		log.Print(b.String())

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
	"flags": func(l logWrap) string { return msgHeaderFlags(l) },
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

func msgHeaderFlags(l logWrap) string {
	h := l.Msg.MsgHeader
	sb := strings.Builder{}
	if h.Response {
		sb.WriteString(" qr")
	}
	if h.Authoritative {
		sb.WriteString(" aa")
	}
	if h.Truncated {
		sb.WriteString(" tc")
	}
	if h.RecursionDesired {
		sb.WriteString(" rd")
	}
	if h.RecursionAvailable {
		sb.WriteString(" ra")
	}
	if h.Zero {
		sb.WriteString(" z")
	}
	if h.AuthenticatedData {
		sb.WriteString(" ad")
	}
	if h.CheckingDisabled {
		sb.WriteString(" cd")
	}
	if h.Security {
		sb.WriteString(" do")
	}
	if h.CompactAnswers {
		sb.WriteString(" co")
	}
	if h.Delegation {
		sb.WriteString(" de")
	}
	return sb.String()[1:]
}
