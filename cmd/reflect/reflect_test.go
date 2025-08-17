package main

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns/internal/dnsperf"
)

// TestReflect tests reflect's performance
func TestReflect(t *testing.T) {
	const count = 10
	timeout := count*2*time.Second + 5*time.Second // run reflect for longer than the test.

	ctx, cancel := context.WithTimeout(context.Background(), timeout)

	cmd := exec.CommandContext(ctx, "./reflect")
	go func() {
		if err := cmd.Run(); err != nil {
			panic(err)
		}
	}()

	queries := strings.NewReader("whoami.miek.nl. A")
	if err := dnsperf.Run(t, queries, "127.0.0.1:8053", "udp", 2*time.Second, count); err != nil {
		t.Fatal(err)
	}
	cancel()
}
