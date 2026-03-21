package uncloud

import (
	"net"

	"codeberg.org/miekg/dns"
	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

type Uncloud struct {
	Path     string
	Name     string
	Listener net.Listener

	db *sqlx.DB
}

func (u *Uncloud) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc { return nil }
