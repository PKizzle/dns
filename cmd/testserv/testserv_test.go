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

// TestTestserv tests testserv's performance. It's only run when an testserve executable is found.
func TestTestserv(t *testing.T) {
	const count = 8
	dir := t.TempDir()
	conffile := dir + "/Conffile"
	os.WriteFile(conffile, []byte(Conffile), 0600)

	for _, network := range []string{"udp", "tcp"} {
		t.Run("testserv-"+network, func(t *testing.T) {
			timeout := count*2*time.Second + 5*time.Second // run reflect for longer than the test.
			ctx, cancel := context.WithTimeout(context.Background(), timeout)

			if _, err := os.Stat("./testserv"); err != nil {
				t.Skip("no testserv binary found in .")
			}

			cmd := exec.CommandContext(ctx, "./testserv", "--conf", conffile, "--port", "8054")
			go func() {
				if err := cmd.Run(); err != nil {
					if _, ok := err.(*exec.ExitError); !ok {
						t.Skip("no working testserv binary found in .")
					}
				}
			}()

			queries := strings.NewReader("whoami.example.org. A")
			if err := dnsperf.Run(t, queries, "127.0.0.1:8054", network, 2*time.Second, count); err != nil {
				t.Fatal(err)
			}
			cancel()
			time.Sleep(2 * time.Second)
		})
	}
}
