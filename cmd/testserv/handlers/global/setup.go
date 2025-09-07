package global

import (
	"log/slog"

	"codeberg.org/miekg/dns/cmd/testserv/internal/conffile"
)

func (g *Global) Setup(d conffile.Dispenser) error {
	if d.Next() {
		switch d.Val() {
		case "root":
			if !d.NextArg() {
				g.Err(d.PropErr())
			}
			g.Root = d.Val()
		case "debug":
			slog.SetLogLoggerLevel(slog.LevelDebug)
		}
	}
	return nil
}
