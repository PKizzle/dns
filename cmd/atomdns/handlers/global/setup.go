package global

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	pp "net/http/pprof"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/conffile"
	"github.com/caddyserver/certmagic"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func (g *Global) Setup(d conffile.Dispenser) error {
	if d.Next() {
		switch d.Val() {
		case "log":
			for d.NextBlock(0) {
				switch d.Val() {
				case "debug":
					g.Debug = true
					slog.SetLogLoggerLevel(slog.LevelDebug)
				case "json":
					jlog := slog.New(slog.NewJSONHandler(os.Stderr, nil))
					slog.SetDefault(jlog)
				case "quiet":
					g.Quiet = true
				default:
					return d.ArgErr()
				}
			}
		case "root":
			if !d.NextArg() {
				d.ArgErr()
			}
			g.Root = d.Val()
			if !filepath.IsAbs(g.Root) {
				pwd, _ := os.Getwd()
				g.Root = filepath.Join(pwd, g.Root)
			}
			if _, err := os.Stat(g.Root); err != nil {
				return err
			}
		case "tls":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			if args[0] != "manual" && args[0] != "lets-encrypt" {
				return d.PropErr(fmt.Errorf("expected %q or %q, got: %s", "manual", "lets-encrypt", args[0]))
			}
			if err := g.SetupTLS(&d); err != nil {
				return err
			}
			switch args[0] {
			case "manual":
				g.OnStartup(func() error {
					log.Info("Startup", "tls", args[0])
					return nil
				})
			case "lets-encrypt":
				if len(g.TlsIPs) != 0 && g.TlsContact != "" {
					g.TlsCertConfig = certmagic.NewDefault()
					ctx, cancel := context.WithCancel(context.Background())
					g.OnStartup(func() error {
						log.Info("Startup", "tls", args[0], "IPs", strings.Join(g.TlsIPs, ","))
						err := certmagic.ManageAsync(ctx, g.TlsIPs)
						if err != nil {
							return err
						}
						return nil
					})
					g.OnShutdown(func() error {
						log.Info("Shutdown", "tls", args[0], "IPs", strings.Join(g.TlsIPs, ","))
						cancel()
						return nil
					})
				}
			}
		case "dns":
			for d.NextBlock(0) {
				switch d.Val() {
				case "addr":
					addrs, err := d.RemainingAddrs()
					if err != nil {
						return d.PropErr(err)
					}
					if len(addrs) != 1 {
						return d.PropErr(fmt.Errorf("need single address"))
					}
					g.Addr = addrs[0]
				case "limits":
					l, err := g.SetupLimits(&d)
					if err != nil {
						return err
					}
					g.MaxTCPQueries = l.MaxTCPQueries
					if l.Servers != -1 {
						g.Servers = l.Servers
					}
				default:
					return d.ArgErr()
				}
			}
			g.OnStartup(func() error {
				log.Info("Startup", "dns", g.Addr, "tcp", g.MaxTCPQueries, "run", g.Servers)
				return nil
			})

		case "dot":
			for d.NextBlock(0) {
				switch d.Val() {
				case "addr":
					addrs, err := d.RemainingAddrs()
					if err != nil {
						return d.PropErr(err)
					}
					if len(addrs) != 1 {
						return d.PropErr(fmt.Errorf("need single address"))
					}
					g.TlsAddr = addrs[0]
				case "limits":
					l, err := g.SetupLimits(&d)
					if err != nil {
						return err
					}
					g.TlsMaxTCPQueries = l.MaxTCPQueries
					if l.Servers != -1 {
						g.TlsServers = l.Servers
					}
				default:
					return d.ArgErr()
				}
			}
			if g.TlsServers > 0 {
				g.OnStartup(func() error {
					log.Info("Startup", "dot", g.TlsAddr, "tcp", g.TlsMaxTCPQueries, "run", g.TlsServers)
					return nil
				})
			}

		case "doh":
			for d.NextBlock(0) {
				switch d.Val() {
				case "addr":
					addrs, err := d.RemainingAddrs()
					if err != nil {
						return d.PropErr(err)
					}
					if len(addrs) != 1 {
						return d.PropErr(fmt.Errorf("need single address"))
					}
					g.HttpAddr = addrs[0]
				case "limits":
					l, err := g.SetupLimits(&d)
					if err != nil {
						return err
					}
					if l.Servers != -1 {
						g.HttpServers = l.Servers
					}
				default:
					return d.ArgErr()
				}
			}
			if g.HttpServers > 0 {
				g.OnStartup(func() error {
					log.Info("Startup", "doh", g.HttpAddr, "run", g.HttpServers, "path", "/dns-query")
					return nil
				})
			}
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
				log.Info("Startup", "/metrics", addr)
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
				log.Info("Shutdown", "/metrics", addr)
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
				log.Info("Startup", "/health", addr)
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
				log.Info("Shutdown", "/health", addr)
				g.HealthListener.Close()
				return nil
			})
			if g.Lameduck > 0 {
				g.OnShutdown(func() error {
					log.Info("Shutdown", "lameduck", g.Lameduck)
					g.HealthListener.Close()
					time.Sleep(g.Lameduck)
					return nil
				})
			}
			ctx := context.Background()
			ctx, cancel := context.WithCancel(ctx)
			g.OnStartup(func() error {
				log.Info("Startup", "health", "overload check")
				go overload(ctx, addr)
				return nil
			})
			g.OnShutdown(func() error {
				log.Info("Shutdown", "health", "overload check")
				cancel()
				return nil
			})
		case "pprof":
			addr := "localhost:6053"
			if d.NextArg() {
				addr = d.Val()
			}
			g.OnStartup(func() error {
				log.Info("Startup", "/debug/pprof", addr)
				ln, err := net.Listen("tcp", addr)
				if err != nil {
					return err
				}
				mux := http.NewServeMux()
				mux.Handle("/metrics", promhttp.Handler())
				mux.HandleFunc("/debug/pprof/", pp.Index)
				mux.HandleFunc("/debug/pprof/cmdline", pp.Cmdline)
				mux.HandleFunc("/debug/pprof/profile", pp.Profile)
				mux.HandleFunc("/debug/pprof/symbol", pp.Symbol)
				mux.HandleFunc("/debug/pprof/trace", pp.Trace)
				server := &http.Server{Handler: mux}
				go func() { server.Serve(ln) }()
				g.PprofListener = ln
				return nil
			})
			g.OnShutdown(func() error {
				log.Info("Shutdown", "/debug/pprof", addr)
				g.PprofListener.Close()
				return nil
			})
		default:
			return d.PropErr()
		}
	}
	g.OnReset(func() {
		g.onceStartup = sync.Once{}
		g.onStartup = []func() error{}

		g.onceShutdown = sync.Once{}
		g.onShutdown = []func() error{}
	})

	return nil
}
