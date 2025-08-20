package dnstest

import (
	"net"

	"codeberg.org/miekg/dns"
)

const port = 40212

// ResponseWriter is useful for writing tests. It uses some fixed values for the client. The
// remote will always be 198.51.100.1 (see RFC 5737) and port 40212.
// The local address is always 127.0.0.1 and port 53.
type ResponseWriter struct {
	TCP bool // if TCP is true we return an TCP connection instead of an UDP one.
}

// ResponseWriter6 returns fixed client and remote address in IPv6.  The remote
// address is always and 2001:db8::1 (see RFC 5156) and port 40212.
// The local address is always ::1 and port 53.
type ResponseWriter6 struct {
	ResponseWriter
}

// LocalAddr returns the local address, always ::1, port 53 (UDP, TCP is t.TCP is true).
func (t *ResponseWriter6) LocalAddr() net.Addr {
	ip := net.ParseIP("::1")
	if t.TCP {
		return &net.TCPAddr{IP: ip, Port: 53}
	}
	return &net.UDPAddr{IP: ip, Port: 53}
}

func (t *ResponseWriter6) RemoteAddr() net.Addr {
	ip := net.ParseIP("2001:db8::1")
	if t.TCP {
		return &net.TCPAddr{IP: ip, Port: port}
	}
	return &net.UDPAddr{IP: ip, Port: port}
}

func (t *ResponseWriter) LocalAddr() net.Addr {
	ip := net.ParseIP("127.0.0.1")
	if t.TCP {
		return &net.TCPAddr{IP: ip, Port: 53}
	}
	return &net.UDPAddr{IP: ip, Port: 53}
}

func (t *ResponseWriter) RemoteAddr() net.Addr {
	ip := net.ParseIP("198.51.100.1")
	if t.TCP {
		return &net.TCPAddr{IP: ip, Port: port}
	}
	return &net.UDPAddr{IP: ip, Port: port}
}

func (t *ResponseWriter) Write(buf []byte) (int, error) { return len(buf), nil }
func (t *ResponseWriter) Conn() net.Conn                { return nil }
func (t *ResponseWriter) Session() *dns.Session         { return nil }
func (t *ResponseWriter) Close() error                  { return nil }
func (t *ResponseWriter) Hijack()                       {}
