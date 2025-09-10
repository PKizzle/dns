package dnsserver

import (
	"codeberg.org/miekg/dns/cmd/testserv/handlers/global"
	"codeberg.org/miekg/dns/cmd/testserv/internal/conffile"
)

//go:generate go run string_generate.go

// Controller is used by handlers to parse their config.
type Controller struct {
	conffile.Dispenser
	Config *global.Global
}

func (c *Controller) OnStartup(fn func() error)  { c.Config.OnStartup(fn) }
func (c *Controller) OnShutdown(fn func() error) { c.Config.OnShutdown(fn) }

// NewTestController create a controller useful for tests.
func NewTestController(input string) Controller {
	d := conffile.NewTestDispenser(input)
	return Controller{Dispenser: d, Config: &global.Global{}}
}
