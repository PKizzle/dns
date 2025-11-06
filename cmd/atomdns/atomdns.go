package main

import (
	"codeberg.org/miekg/dns/cmd/atomdns/atom"
)

//go:generate go run man_generate.go

const version = "037"

func main() { atom.Run(version) }
