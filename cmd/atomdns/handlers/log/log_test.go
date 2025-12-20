package log_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/atomtest"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/log"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/dnstest"
)

func TestLog(t *testing.T) {
	l := &log.Log{
		Contexts: map[string][]string{
			"hello": []string{"here", "there"},
		},
	}

	b := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(b, nil))
	slog.SetDefault(logger)
	m := dnstest.NewMsg()

	ctx := context.Background()
	ctx = dnsctx.WithValue(ctx, "hello/here", "not far")
	ctx = dnsctx.WithValue(ctx, "hello/there", "far")

	tw := dnstest.NewRecorder(&dnstest.ResponseWriter{})
	l.HandlerFunc(atomtest.Echo).ServeDNS(ctx, tw, m)
	if !strings.Contains(b.String(), `hello.here="not far" hello.there=far`) {
		t.Fatal("expected context items to show up, got none")
	}
}
