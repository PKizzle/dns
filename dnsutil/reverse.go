package dnsutil

import "strings"

const (
	// IP4arpa is the reverse tree suffix for v4 IP addresses.
	IP4arpa = ".in-addr.arpa."
	// IP6arpa is the reverse tree suffix for v6 IP addresses.
	IP6arpa = ".ip6.arpa."
)

// IsReverse returns 0 if name is not a reverse zone. Anything > 0 indicates
// name is in a reverse zone. The returned integer will be 1 for in-addr.arpa. (IPv4)
// and 2 for ip6.arpa. (IPv6). A canonical name is assumed.
func IsReverse(s string) int {
	if strings.HasSuffix(s, IP4arpa) {
		return 1
	}
	if strings.HasSuffix(s, IP6arpa) {
		return 2
	}
	return 0
}
