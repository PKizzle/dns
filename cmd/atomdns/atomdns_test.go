package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns/internal/dnsperf"
)

const Conffile = `
whoami.example.org {
	metrics
	any
    whoami
}
`

// TestAtomdns tests atomdns' performance. It's only run when an atomdns executable is found.
func TestAtomdns(t *testing.T) {
	const count = 8
	dir := t.TempDir()
	conffile := dir + "/Conffile"
	os.WriteFile(conffile, []byte(Conffile), 0600)

	for _, network := range []string{"udp", "tcp"} {
		t.Run("atomdns-"+network, func(t *testing.T) {
			timeout := count*2*time.Second + 5*time.Second // run reflect for longer than the test.
			ctx, cancel := context.WithTimeout(context.Background(), timeout)

			if _, err := os.Stat("./atomdns"); err != nil {
				t.Skip("no atomdns binary found in .")
			}

			cmd := exec.CommandContext(ctx, "./atomdns", "--conf", conffile, "--port", "8054")
			go func(t *testing.T) {
				if err := cmd.Run(); err != nil {
					if _, ok := err.(*exec.ExitError); !ok {
						t.Skip("no working atomdns binary found in .")
					}
				}
			}(t)

			queries := strings.NewReader("whoami.example.org. A")
			if err := dnsperf.Run(t, queries, "127.0.0.1:8054", network, 2*time.Second, count); err != nil {
				t.Fatal(err)
			}
			cancel()
			time.Sleep(1 * time.Second)
		})
	}
}
