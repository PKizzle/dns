package main

import (
	"codeberg.org/miekg/dns/cmd/atomdns/atom"
)

//go:generate go run man_generate.go

func main() { atom.Run() }
