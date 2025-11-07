package dnsutil

import (
	"net"

	"codeberg.org/miekg/dns"
)

// RemoteIP returns the IP address of the client making the request.
func RemoteIP(w dns.ResponseWriter) string { return ip(w.RemoteAddr().String()) }

// LocalIP gets the IP address of server handling the request.
func LocalIP(w dns.ResponseWriter) string { return ip(w.LocalAddr().String()) }

// RemotePort gets the port of the client making the request.
func RemotePort(w dns.ResponseWriter) string { return port(w.RemoteAddr().String()) }

// LocalPort gets the local port of the server handling the request.
func LocalPort(w dns.ResponseWriter) string { return port(w.LocalAddr().String()) }

func port(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err != nil {
		return ""
	} else {
		return port
	}
}

func ip(addr string) string {
	if ip, _, err := net.SplitHostPort(addr); err != nil {
		return ""
	} else {
		return ip
	}
}

// Network returns the network used to make the request, this can be udp or tcp.
func Network(w dns.ResponseWriter) string {
	if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		return "udp"
	}
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		return "tcp"
	}
	return "udp"
}

// Family returns the family of the transport, 1 for IPv4 and 2 for IPv6 as defined by IANA.
func Family(w dns.ResponseWriter) int {
	var a net.IP
	ip := w.RemoteAddr()
	if i, ok := ip.(*net.UDPAddr); ok {
		a = i.IP
	}
	if i, ok := ip.(*net.TCPAddr); ok {
		a = i.IP
	}

	if a.To4() != nil {
		return IPv4Family
	}
	return IPv6Family
}

// The IP address families are defined by IANA, and can be found at https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
const (
	IPv4Family = 1
	IPv6Family = 2
)
