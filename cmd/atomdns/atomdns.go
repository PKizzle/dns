package main

import (
	"codeberg.org/miekg/dns/cmd/atomdns/atom"
)

//go:generate go run man_generate.go

const version = "034"

func main() { atom.Run(version) }
