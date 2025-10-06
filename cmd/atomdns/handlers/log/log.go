package log

import (
	"context"
	"log/slog"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

type Log int

var logger = slog.Default()

func (l *Log) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		if !state.Load() {
			next.ServeDNS(ctx, w, r)
			return
		}

		logger.
			With("remote", dnsutil.RemoteIP(w)).
			With("port", dnsutil.RemotePort(w)).
			With(slog.Int("id", int(r.ID))).
			With("type", func() string { _, t := dnsutil.Question(r); return dnsutil.TypeToString(t) }()).
			With("class", dnsutil.ClassToString(r.Question[0].Header().Class)).
			With("name", func() string { z, _ := dnsutil.Question(r); return z }()).
			With("network", dnsutil.Network(w)).
			With(slog.Int("size", len(r.Data))).
			With(slog.Int("bufsize", func() int {
				if r.UDPSize < 512 {
					return 512
				}
				return int(r.UDPSize)
			}())).
			With("opcode", dnsutil.OpcodeToString(r.Opcode)).
			Info(dns.Zone(ctx))

		next.ServeDNS(ctx, w, r)
	})
}
