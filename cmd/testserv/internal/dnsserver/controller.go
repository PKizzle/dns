package dnsserver

import (
	"codeberg.org/miekg/dns/cmd/testserv/handlers/global"
	"codeberg.org/miekg/dns/cmd/testserv/internal/conffile"
)

// Controller is used by handlers to parse their config.
type Controller struct {
	conffile.Dispenser
	Config *global.Global
}
