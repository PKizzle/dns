package dns

import (
	"net"

	"codeberg.org/miekg/dns/internal/pack"
	"codeberg.org/miekg/dns/internal/unpack"
	"golang.org/x/crypto/cryptobyte"
)

func packAPL(data []APLPrefix, msg []byte, off int) (int, error) {
	var err error
	for i := range data {
		off, err = packAPLPrefix(&data[i], msg, off)
		if err != nil {
			return len(msg), err
		}
	}
	return off, nil
}

func packAPLPrefix(p *APLPrefix, msg []byte, off int) (int, error) {
	if len(p.Network.IP) != len(p.Network.Mask) {
		return len(msg), &pack.Error{Err: "address and mask lengths don't match"}
	}

	var err error
	prefix, _ := p.Network.Mask.Size()
	addr := p.Network.IP.Mask(p.Network.Mask)[:(prefix+7)/8]

	switch len(p.Network.IP) {
	case net.IPv4len:
		off, err = pack.Uint16(1, msg, off)
	case net.IPv6len:
		off, err = pack.Uint16(2, msg, off)
	default:
		err = &pack.Error{Err: "unrecognized address family"}
	}
	if err != nil {
		return len(msg), err
	}

	off, err = pack.Uint8(uint8(prefix), msg, off)
	if err != nil {
		return len(msg), err
	}

	var n uint8
	if p.Negation {
		n = 0x80
	}

	// trim trailing zero bytes as specified in RFC3123 Sections 4.1 and 4.2.
	i := len(addr) - 1
	for ; i >= 0 && addr[i] == 0; i-- {
	}
	addr = addr[:i+1]

	adflen := uint8(len(addr)) & 0x7f
	off, err = pack.Uint8(n|adflen, msg, off)
	if err != nil {
		return len(msg), err
	}

	if off+len(addr) > len(msg) {
		return len(msg), &pack.Error{Err: "overflow APL prefix"}
	}
	off += copy(msg[off:], addr)

	return off, nil
}

func unpackAPL(s *cryptobyte.String) ([]APLPrefix, error) {
	var prefixes []APLPrefix
	for !s.Empty() {
		prefix, err := unpackAPLPrefix(s)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func unpackAPLPrefix(s *cryptobyte.String) (APLPrefix, error) {
	var (
		family       uint16
		prefix, nlen byte
	)
	if !s.ReadUint16(&family) ||
		!s.ReadUint8(&prefix) ||
		!s.ReadUint8(&nlen) {
		return APLPrefix{}, unpack.ErrOverflow
	}

	var ip net.IP
	switch family {
	case 1:
		ip = make(net.IP, net.IPv4len)
	case 2:
		ip = make(net.IP, net.IPv6len)
	default:
		return APLPrefix{}, &unpack.Error{Err: "unrecognized APL address family"}
	}
	if int(prefix) > 8*len(ip) {
		return APLPrefix{}, &unpack.Error{Err: "APL prefix too long"}
	}
	afdlen := int(nlen & 0x7f)
	if afdlen > len(ip) {
		return APLPrefix{}, &unpack.Error{Err: "APL length too long"}
	}
	if !s.CopyBytes(ip[:afdlen]) {
		return APLPrefix{}, unpack.ErrOverflow
	}

	// Address MUST NOT contain trailing zero bytes per RFC3123 Sections 4.1 and 4.2.
	if afdlen > 0 && ip[afdlen-1] == 0 {
		return APLPrefix{}, &Error{err: "extra APL address bits"}
	}

	return APLPrefix{
		Negation: nlen&0x80 != 0,
		Network: net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(int(prefix), 8*len(ip)),
		},
	}, nil
}
