//go:build windows || darwin

// NOTICE(stek29): darwin supports PKTINFO in sendmsg, but it unbinds sockets, see https://github.com/miekg/dns/issues/724

package dns

import "net"

var oobSize = func() int { return 0 }()

func setUDPSocketOptions(*net.UDPConn) error { return nil }
func parseFromOOB([]byte, net.IP) net.IP     { return nil }
func sourceFromOOB([]byte) []byte            { return nil }
