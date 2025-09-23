package dnszone

import (
	"codeberg.org/miekg/dns"
)

// Interface defines the methods for each db* implementation. This is currently unused, and if used
// this needs to live in the pkg/db or something, not tucked away here.
//
// This is the interface dbfile implements on top of the b-tree. And dbsqlite on top of an SQLite database.
type Interface interface {
	// Load loads a zone.
	Load() error
	// Retrieve takes an incoming message and prepares a reply that is ready to be send back to the client.
	Retrieve(*dns.Msg, *Restart) *dns.Msg
	// Get returns the node under key. The boolean is true when something is found.
	Get(string) (Node, bool)
	// Previous returns the previous node for string. If the node under key exists that one is returned.
	Previous(string) Node
	// Set sets a node in the zone. It must take care to also fill out any empty non-terminals that are
	// needed.
	Set(Node) string
	// Apex returns the apex of the zone.
	Apex() Node
	// Origin returns the origin of the zone as string.
	Origin() string
	// Walk walks the entire walk starting at the apex.
	Walk(func(Node) bool)
	// AuthoritativeWalk walks the entire zone starting at the apex, but skips non-authoritative records:
	// delegated (or should have been delegated) and glue recors.
	AuthoritativeWalk(func(Node, bool) bool)
}
