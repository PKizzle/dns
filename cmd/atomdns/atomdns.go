package main

import (
	"codeberg.org/miekg/dns/cmd/atomdns/atom"
)

//go:generate go run man_generate.go
//go:generate go run release_generate.go

const version = "063"

func main() { atom.Run(version) }
