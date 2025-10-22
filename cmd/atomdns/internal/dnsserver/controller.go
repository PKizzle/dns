package dnsserver

import (
	"path/filepath"

	"codeberg.org/miekg/dns/cmd/atomdns/handlers/global"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/conffile"
)

//go:generate go run string_generate.go

// Controller is used by handlers to parse their config.
type Controller struct {
	conffile.Dispenser
	Global *global.Global
}

// OnStartup and OnShutdown can be used by handlers to register startup and shutdown functions. Each function
// is execute once during starting and shutting of the server.
func (c *Controller) OnStartup(fn func() error)  { c.Global.OnStartup(fn) }
func (c *Controller) OnShutdown(fn func() error) { c.Global.OnShutdown(fn) }
func (c *Controller) OnReset(fn func())          { c.Global.OnReset(fn) }

// NewTestController create a controller useful for tests.
func NewTestController(input string) *Controller {
	d := conffile.NewTestDispenser(input)
	return &Controller{Dispenser: d, Global: &global.Global{}}
}

func (c *Controller) Path() string {
	if filepath.IsAbs(c.Dispenser.Val()) {
		return c.Dispenser.Val()
	}
	return filepath.Join(c.Global.Root, c.Dispenser.Val())
}

func (c *Controller) RemainingPaths() []string {
	args := c.RemainingArgs()
	if len(args) == 0 {
		return nil
	}
	paths := make([]string, len(args))

	for i, arg := range args {
		if filepath.IsAbs(arg) {
			paths[i] = arg
			continue
		}
		paths[i] = filepath.Join(c.Global.Root, arg)
	}
	return paths
}
