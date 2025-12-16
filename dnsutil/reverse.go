package dnsutil

import (
	"net"
	"net/netip"
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
// name is in a reverse zone. The returned integer will be [IPv4Family] for in-addr.arpa. (IPv4)
// and [IPv6Family] for ip6.arpa. (IPv6), see [Family]. A canonical name is assumed.
func IsReverse(s string) int {
	if strings.HasSuffix(s, IP4arpa) {
		return IPv4Family
	}
	if strings.HasSuffix(s, IP6arpa) {
		return IPv6Family
	}
	return 0
}

const hexDigit = "0123456789abcdef"

// ReverseAddr returns the in-addr.arpa. or ip6.arpa. hostname of the IP
// address suitable for reverse DNS ([dns.PTR]) record lookups. Also see [AddrReverse].
func ReverseAddr(ip netip.Addr) (arpa string) {
	if ip.Is4() {
		v4 := ip.As4()
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
	v6 := ip.As16()
	// Add it, in reverse, to the buffer
	for i := len(v6) - 1; i >= 0; i-- {
		v := v6[i]
		buf = append(buf, hexDigit[v&0xF], '.', hexDigit[v>>4], '.')
	}
	// Append "ip6.arpa." and return (buf already has the final .)
	buf = append(buf, IP6arpa[1:]...)
	return string(buf)
}

// AddrReverse turns a standard [dns.PTR] reverse record name into an IP address.
// 54.119.58.176.in-addr.arpa. becomes 176.58.119.54. If the conversion
// fails nil is returned. Also see [ReverseAddr].
func AddrReverse(s string) (ip netip.Addr) {
	switch IsReverse(s) {
	default:
		fallthrough
	case 0:
		return netip.Addr{}
	case IPv4Family:
		ipstr := strings.TrimSuffix(s, IP4arpa)
		return rev(strings.Split(ipstr, "."), IPv4Family)
	case IPv6Family:
		ipstr := strings.TrimSuffix(s, IP6arpa)
		return rev(strings.Split(ipstr, "."), IPv6Family)
	}
}

func rev(slice []string, fam int) netip.Addr {
	for i := 0; i < len(slice)/2; i++ {
		j := len(slice) - i - 1
		slice[i], slice[j] = slice[j], slice[i]
	}
	addr := ""
	switch fam {
	case IPv4Family:
		addr = strings.Join(slice, ".")
	case IPv6Family:
		slice6 := []string{}
		for i := 0; i < len(slice)/4; i++ {
			slice6 = append(slice6, strings.Join(slice[i*4:i*4+4], ""))
		}
		addr = strings.Join(slice6, ":")
	}
	ip, _ := netip.ParseAddr(addr)
	return ip
}
