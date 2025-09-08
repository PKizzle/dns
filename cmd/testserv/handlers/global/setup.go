package global

import (
	"log/slog"
	"net/http"

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
		case "debug":
			slog.SetLogLoggerLevel(slog.LevelDebug)
		case "metrics":
			addr := "localhost:9153"
			if d.NextArg() {
				addr = d.Val()
			}
			http.Handle("/metrics", promhttp.Handler())
			go func() {
				if err := http.ListenAndServe(addr, nil); err != nil {
					slog.Error("Failed to setup metrics handler failed: " + err.Error())
				}
			}()
		}
	}
	return nil
}
