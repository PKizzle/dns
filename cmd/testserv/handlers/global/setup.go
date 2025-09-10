package global

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns/cmd/testserv/internal/conffile"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func (g *Global) Setup(d conffile.Dispenser) error {
	if d.Next() {
		switch d.Val() {
		case "root":
			if !d.NextArg() {
				d.PropErr()
			}
			g.Root = d.Val()
			if !filepath.IsAbs(g.Root) {
				pwd, _ := os.Getwd()
				g.Root = filepath.Join(pwd, g.Root)
			}
		case "debug":
			slog.SetLogLoggerLevel(slog.LevelDebug)
		case "metrics":
			g.MetricsN = 10
			addr := "localhost:9153"
			if d.NextArg() {
				if !strings.HasPrefix(d.Val(), "/") {
					addr = d.Val()
				} else {
					n, err := strconv.Atoi(d.Val()[1:])
					if err != nil || n < 0 {
						return d.PropErr(fmt.Errorf("not a (positive) number: %q", d.Val()[1:]))
					}
				}
			}
			if d.NextArg() {
				addr = d.Val()
			}
			g.OnStartup(func() error {
				// TODO(miek): do better and catch error, while using 'go func'
				http.Handle("/metrics", promhttp.Handler())
				go func() {
					if err := http.ListenAndServe(addr, nil); err != nil {
						slog.Error("Failed to setup metrics handler failed: " + err.Error())
					}
				}()
				return nil
			})
			g.OnShutdown(func() error { return nil })
		}
	}
	return nil
}
