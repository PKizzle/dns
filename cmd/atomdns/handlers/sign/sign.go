// Package sign implements a zone signer as a hander.
package sign

import (
	"context"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
)

type Sign struct {
	Path      string
	Directory string
	KeyPairs  []KeyPair
	pool      *dns.Pool

	Zones map[string]*zone.Zone
	ttl   uint32 // default ttl on all records

	ctx    context.Context
	cancel context.CancelFunc
}

func (s *Sign) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) { next.ServeDNS(ctx, w, r) })
}

// Various duration constants for signing of the zones.
const (
	expireDays = 9 * Day // max time allowed before expiration

	signatureExpire    = 32 * Day       // sign for 32 days
	signatureInception = -3 * time.Hour // -(2+1) hours, be sure to catch daylight saving time and such, jitter is subtracted

	inceptionJitter  = -18 * time.Hour // default max jitter for the inception
	expirationJitter = 100 * time.Hour // default max jitter for the expiration
)

const Day = 24 * time.Hour
