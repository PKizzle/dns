package dbhost

import (
	"context"
	"sync"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
)

type Dbhost struct {
	Path string
	TTL  int

	Data         map[string]dnszone.Node
	sync.RWMutex // protects Data
}

func (d *Dbhost) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		//...
	})
}
