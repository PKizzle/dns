package dns_test

import (
	"testing"

	"codeberg.org/miekg/dns"
)

// YO is a private RR.
type YO struct {
	Hdr      dns.Header
	Priority uint8
	Yo       string `dns:"txt"`
}

// Typer interface
func (rr *YO) Type() uint16 { return 65281 }

// RR interface
func (rr *YO) Header() *dns.Header { return &rr.Hdr }
func (rr *YO) String() string      { return rr.Hdr.String() + "" }

// Test if an externally defined RR can be scanned, packed, and unpacked.
func TestExternalRR(t *testing.T) {
}
