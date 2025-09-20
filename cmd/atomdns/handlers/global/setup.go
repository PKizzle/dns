package global

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/conffile"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func (g *Global) Setup(d conffile.Dispenser) error {
	g.Root, _ = os.Getwd()
	if d.Next() {
		switch d.Val() {
		case "root":
			if !d.NextArg() {
				d.ArgErr()
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
				log.Info("Start: /metrics")
				ln, err := net.Listen("tcp", addr)
				if err != nil {
					return err
				}
				mux := http.NewServeMux()
				mux.Handle("/metrics", promhttp.Handler())
				server := &http.Server{Handler: mux}
				go func() { server.Serve(ln) }()
				g.MetricsListener = ln
				return nil
			})
			g.OnShutdown(func() error {
				log.Info("Shutdown: /metrics")
				g.MetricsListener.Close()
				return nil
			})
		case "health":
			addr := ":8080"
			if d.Next() {
				addr = d.Val()
			}
			if d.Next() {
				delay, err := time.ParseDuration(d.Val())
				if err != nil || delay < 0 {
					return d.PropErr(fmt.Errorf("not a (positive) number: %q", d.Val()))
				}
				g.Lameduck = delay
			}
			g.OnStartup(func() error {
				log.Info("Start: /health")
				ln, err := net.Listen("tcp", addr)
				if err != nil {
					return err
				}
				mux := http.NewServeMux()
				mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					io.WriteString(w, http.StatusText(http.StatusOK))
				})
				server := &http.Server{Handler: mux}
				go func() { server.Serve(ln) }()
				g.HealthListener = ln
				return nil
			})

			g.OnShutdown(func() error {
				log.Info("Shutdown: /health")
				g.HealthListener.Close()
				return nil
			})
			if g.Lameduck > 0 {
				g.OnShutdown(func() error {
					log.Info("Shutdown: lameduck mode for " + g.Lameduck.String())
					g.HealthListener.Close()
					return nil
				})
			}
		}
	}
	return nil
}
