//go:build windows || darwin

// NOTICE(stek29): darwin supports PKTINFO in sendmsg, but it unbinds sockets, see https://github.com/miekg/dns/issues/724

package dns

import "net"

// Session is a small strucures that keep track of where the (potential) UDP message came from.
type Session struct {
	raddr *net.UDPAddr // address from [net.ReadMsgUDP]
	// oob data also returned, this is needed to route to the correct interface. As these are small fixed
	// slices it makes sense to use a sync.Pool, to be able to override this behavior an
	oobdata []byte
}

func (s *Session) RemoteAddr() net.Addr { return s.raddr }

var oobSize = func() int { return 0 }()

func setUDPSocketOptions(*net.UDPConn) error { return nil }
func parseDstFromOOB([]byte, net.IP) net.IP  { return nil }
