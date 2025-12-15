package main

import (
	"context"
	"log"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns/internal/dnsperf"
)

// TestReflect tests reflect's performance.
func TestReflect(t *testing.T) {
	const count = 8
	for _, network := range []string{"udp", "tcp"} {
		t.Run("reflect-"+network, func(t *testing.T) {
			timeout := count*2*time.Second + 5*time.Second // run reflect for longer than the test.
			ctx, cancel := context.WithTimeout(context.Background(), timeout)

			if _, err := os.Stat("./reflect"); err != nil {
				t.Skip("no reflect binary found in .")
			}

			cmd := exec.CommandContext(ctx, "./reflect")
			go func() {
				if err := cmd.Run(); err != nil {
					if _, ok := err.(*exec.ExitError); !ok {
						log.Fatal("no working reflect binary found in .")
					}
				}
			}()

			queries := strings.NewReader("whoami.miek.nl. A")
			if err := dnsperf.Run(t, queries, "127.0.0.1:8053", network, 2*time.Second, count); err != nil {
				t.Fatal(err)
			}
			cancel()
			time.Sleep(1 * time.Second)
		})
	}
}
