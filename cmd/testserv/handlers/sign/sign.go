// Package sign implements a zone signer as a plugin.
package sign

import (
	"context"
	"time"

	"codeberg.org/miekg/dns/cmd/testserv/handlers/dbfile/zone"
)

type Sign struct {
	Path      string
	Directory string
	Pairs     []Pair

	Zones map[string]*zone.Zone
	ttl   uint32 // default ttl on all records

	ctx    context.Context
	cancel context.CancelFunc
}

// Various duration constants for signing of the zones.
const (
	durationExpireDays          = 9 * 24 * time.Hour  // max time allowed before expiration
	durationResignDays          = 6 * 24 * time.Hour  // if the last sign happened this long ago, sign again
	durationSignatureExpireDays = 32 * 24 * time.Hour // sign for 32 days

	durationInceptionJitter     = -18 * time.Hour    // default max jitter for the inception
	durationExpirationDayJitter = 5 * 24 * time.Hour // default max jitter for the expiration

	durationSignatureInceptionHours = -3 * time.Hour // -(2+1) hours, be sure to catch daylight saving time and such, jitter is subtracted
	durationRefreshHours            = 5 * time.Hour  // check zones every 5 hours
)
