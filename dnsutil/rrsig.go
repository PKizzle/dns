package dnsutil

import "codeberg.org/miekg/dns"

// RRSIGCover returns true any of the types are covered by this RRSIG.
func RRSIGCover(rr *dns.RRSIG, types ...uint16) bool {
	for _, t := range types {
		if rr.TypeCovered == t {
			return true
		}
	}
	return false
}
