package dns

import (
	"net"

	"codeberg.org/miekg/dns/internal/pack"
	"codeberg.org/miekg/dns/internal/unpack"
	"golang.org/x/crypto/cryptobyte"
)

func unpackIPSECGateway(s *cryptobyte.String, msgBuf []byte, gatewayType uint8) (net.IP, string, error) {
	var (
		addr net.IP
		name string
		err  error
	)
	switch gatewayType {
	case IPSECGatewayNone: // do nothing
	case IPSECGatewayIPv4:
		addr, err = unpack.A(s)
	case IPSECGatewayIPv6:
		addr, err = unpack.AAAA(s)
	case IPSECGatewayHost:
		name, err = unpack.Name(s, msgBuf)
	}
	return addr, name, err
}

func packIPSECGateway(addr net.IP, gateway string, msg []byte, off int, t uint8, compression map[string]uint16, compress bool) (int, error) {
	var err error

	switch t {
	case IPSECGatewayNone: // do nothing
	case IPSECGatewayIPv4:
		off, err = pack.A(addr, msg, off)
	case IPSECGatewayIPv6:
		off, err = pack.AAAA(addr, msg, off)
	case IPSECGatewayHost:
		off, err = pack.Name(gateway, msg, off, compression, compress)
	}
	return off, err
}
