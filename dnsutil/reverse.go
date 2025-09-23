package dnsutil

import (
	"net"
	"strconv"
	"strings"
)

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

const hexDigit = "0123456789abcdef"

// ReverseAddr returns the in-addr.arpa. or ip6.arpa. hostname of the IP
// address suitable for reverse DNS ([dns.PTR]) record lookups. Also see [AddrReverse].
func ReverseAddr(ip net.IP) (arpa string) {
	if v4 := ip.To4(); v4 != nil {
		buf := make([]byte, 0, net.IPv4len*4+len(IP4arpa))
		// Add it, in reverse, to the buffer
		for i := len(v4) - 1; i >= 0; i-- {
			buf = strconv.AppendInt(buf, int64(v4[i]), 10)
			buf = append(buf, '.')
		}
		// Append "in-addr.arpa." and return (buf already has the final .)
		buf = append(buf, IP4arpa[1:]...)
		return string(buf)
	}
	// Must be IPv6
	buf := make([]byte, 0, net.IPv6len*4+len(IP6arpa))
	// Add it, in reverse, to the buffer
	for i := len(ip) - 1; i >= 0; i-- {
		v := ip[i]
		buf = append(buf, hexDigit[v&0xF], '.', hexDigit[v>>4], '.')
	}
	// Append "ip6.arpa." and return (buf already has the final .)
	buf = append(buf, IP6arpa[1:]...)
	return string(buf)
}

// AddrReverse turns a standard [dns.PTR] reverse record name into an IP address.
// 54.119.58.176.in-addr.arpa. becomes 176.58.119.54. If the conversion
// fails nil is returned. Also see [ReverseAddr].
func AddrReverse(s string) (ip net.IP) {
	switch IsReverse(s) {
	case 0:
		return nil
	case 1:
		ipstr := strings.TrimSuffix(s, IP4arpa)
		return rev(strings.Split(ipstr, "."))
	case 2:
		ipstr := strings.TrimSuffix(s, IP6arpa)
		return rev6(strings.Split(ipstr, "."))
	}
	return nil
}

func rev(slice []string) net.IP {
	for i := 0; i < len(slice)/2; i++ {
		j := len(slice) - i - 1
		slice[i], slice[j] = slice[j], slice[i]
	}
	return net.ParseIP(strings.Join(slice, ".")).To4()
}

// reverse6 reverse the segments and combine them according to RFC3596:
// b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2
// is reversed to 2001:db8::567:89ab
func rev6(slice []string) net.IP {
	for i := 0; i < len(slice)/2; i++ {
		j := len(slice) - i - 1
		slice[i], slice[j] = slice[j], slice[i]
	}
	slice6 := []string{}
	for i := 0; i < len(slice)/4; i++ {
		slice6 = append(slice6, strings.Join(slice[i*4:i*4+4], ""))
	}
	return net.ParseIP(strings.Join(slice6, ":")).To16()
}
