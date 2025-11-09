package localaddr

import (
	"net"

	"codeberg.org/miekg/dns/dnsutil"
)

// Source returns the address from sources that matches the family. If none match, nil is returned.
func Source(family int, sources []string) net.IP {
	for _, s := range sources {
		sip := net.ParseIP(s)
		switch family {
		case dnsutil.IPv4Family:
			if x := sip.To4(); x != nil {
				return x
			}
		case dnsutil.IPv6Family:
			if sip.To4() == nil {
				return sip
			}
		}
	}
	return nil
}
