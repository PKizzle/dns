package dns

import (
	"net"

	"codeberg.org/miekg/dns/internal/ddd"
	"codeberg.org/miekg/dns/internal/pack"
	"codeberg.org/miekg/dns/internal/unpack"
	"golang.org/x/crypto/cryptobyte"
)

// helper functions called from the generated zmsg.go - among others
// all need to move to internal/pack or internal/unpack

// unpackHeader unpacks an RR header advancing msg.
func unpackHeader(msg *cryptobyte.String, msgBuf []byte) (h Header, rdlength uint16, err error) {
	h.Name, err = unpack.Name(msg, msgBuf)
	if err != nil {
		return h, 0, err
	}
	if !msg.ReadUint16(&h.t) ||
		!msg.ReadUint16(&h.Class) ||
		!msg.ReadUint32(&h.TTL) ||
		!msg.ReadUint16(&rdlength) {
		return h, rdlength, unpack.ErrTruncatedMessage
	}
	return h, rdlength, nil
}

// packHeader packs an RR header, returning the off to the end of the header.
// See PackName for documentation about the compression.
func (h Header) packHeader(msg []byte, off int, rrtype uint16, compress map[string]uint16) (int, error) {
	if off == len(msg) {
		return off, nil
	}
	off, err := pack.Name(h.Name, msg, off, compress, true)
	if err != nil {
		return len(msg), err
	}
	off, err = pack.Uint16(rrtype, msg, off)
	if err != nil {
		return len(msg), err
	}
	off, err = pack.Uint16(h.Class, msg, off)
	if err != nil {
		return len(msg), err
	}
	off, err = pack.Uint32(h.TTL, msg, off)
	if err != nil {
		return len(msg), err
	}
	off, err = pack.Uint16(0, msg, off) // The RDLENGTH field will be set later in packRR.
	if err != nil {
		return len(msg), err
	}
	return off, nil
}

// helper helper functions.

func unpackStringTxt(s *cryptobyte.String) ([]string, error) {
	return unpackTxt(s)
}

func packStringTxt(s []string, msg []byte, off int) (int, error) {
	off, err := packTxt(s, msg, off)
	if err != nil {
		return len(msg), err
	}
	return off, nil
}

func unpackOpt(s *cryptobyte.String) ([]EDNS0, error) {
	edns0 := []EDNS0{}
	for !s.Empty() {
		var (
			code uint16
			data cryptobyte.String
		)
		if !s.ReadUint16(&code) || !s.ReadUint16LengthPrefixed(&data) {
			return nil, unpack.ErrOverflow
		}
		var option EDNS0
		if newFn, ok := CodeToRR[code]; ok {
			option = newFn()
		} else {
			return nil, unpack.Errorf("unknown OPT code %d", code)
		}
		if err := unpackOptionCode(option, &data); err != nil {
			return nil, err
		}
		edns0 = append(edns0, option)
	}
	return edns0, nil
}

func packOpt(options []EDNS0, msg []byte, off int) (int, error) {
	for _, option := range options {
		l := option.Len()
		if off+l >= len(msg) {
			return len(msg), pack.ErrBuf
		}
		code := RRToCode(option) // TODO(miek): unknown codes, caught later

		pack.Uint16(code, msg, off)
		pack.Uint16(uint16(l-tlv), msg, off+2)
		optionoff, err := packOptionCode(option, msg, off+4)
		if err != nil {
			return len(msg), err
		}

		off += optionoff + l
	}
	return off, nil
}

func unpackStringOctet(s *cryptobyte.String) (string, error) { return unpack.StringAny(s, len(*s)) }

func packStringOctet(s string, msg []byte, off int) (int, error) {
	off, err := packOctetString(s, msg, off)
	if err != nil {
		return len(msg), err
	}
	return off, nil
}

func unpackNsec(s *cryptobyte.String) ([]uint16, error) {
	var nsec []uint16
	lastwindow := -1
	for !s.Empty() {
		var (
			window byte
			bits   cryptobyte.String
		)
		if !s.ReadUint8(&window) ||
			!s.ReadUint8LengthPrefixed(&bits) {
			return nsec, unpack.ErrOverflow
		}
		if int(window) <= lastwindow {
			// RFC 4034: Blocks are present in the NSEC RR RDATA in
			// increasing numerical order.
			return nsec, &unpack.Error{Err: "out of order NSEC(3) BLock in type bitmap"}
		}
		if len(bits) == 0 {
			// RFC 4034: Blocks with no types present MUST NOT be included.
			return nsec, &unpack.Error{Err: "empty NSEC(3) block in type bitmap"}
		}
		if len(bits) > 32 {
			return nsec, &unpack.Error{Err: "NSEC(3) block too long in type bitmap"}
		}

		// Walk the bytes in the window and extract the type bits
		for i, b := range bits {
			for n := uint(0); n < 8; n++ {
				if b&(1<<(7-n)) != 0 {
					nsec = append(nsec, uint16(int(window)*256+i*8+int(n)))
				}
			}
		}

		lastwindow = int(window)
	}
	return nsec, nil
}

// typeBitMapLen is a helper function which computes the "maximum" length of
// a the NSEC Type BitMap field.
func typeBitMapLen(bitmap []uint16) int {
	var l int
	var lastwindow, lastlength uint16
	for _, t := range bitmap {
		window := t / 256
		length := (t-window*256)/8 + 1
		if window > lastwindow && lastlength != 0 { // New window, jump to the new off
			l += int(lastlength) + 2
			lastlength = 0
		}
		if window < lastwindow || length < lastlength {
			// packNsec would return Error{err: "nsec bits out of order"} here, but
			// when computing the length, we want do be liberal.
			continue
		}
		lastwindow, lastlength = window, length
	}
	l += int(lastlength) + 2
	return l
}

func packNsec(bitmap []uint16, msg []byte, off int) (int, error) {
	if len(bitmap) == 0 {
		return off, nil
	}
	if off > len(msg) {
		return off, &pack.Error{Err: "overflow NSEC(3)"}
	}
	toZero := msg[off:]
	if maxLen := typeBitMapLen(bitmap); maxLen < len(toZero) {
		toZero = toZero[:maxLen]
	}
	for i := range toZero {
		toZero[i] = 0
	}
	var lastwindow, lastlength uint16
	for _, t := range bitmap {
		window := t / 256
		length := (t-window*256)/8 + 1
		if window > lastwindow && lastlength != 0 { // New window, jump to the new off
			off += int(lastlength) + 2
			lastlength = 0
		}
		if window < lastwindow || length < lastlength {
			return len(msg), &pack.Error{Err: "NSEC(3) bits out of order"}
		}
		if off+2+int(length) > len(msg) {
			return len(msg), &pack.Error{Err: "overflow NSEC(3)"}
		}
		// Setting the window #
		msg[off] = byte(window)
		// Setting the octets length
		msg[off+1] = byte(length)
		// Setting the bit value for the type in the right octet
		msg[off+1+int(length)] |= byte(1 << (7 - t%8))
		lastwindow, lastlength = window, length
	}
	off += int(lastlength) + 2
	return off, nil
}

func unpackNames(s *cryptobyte.String, msgBuf []byte) ([]string, error) {
	var names []string
	for !s.Empty() {
		name, err := unpack.Name(s, msgBuf)
		if err != nil {
			return names, err
		}
		names = append(names, name)
	}
	return names, nil
}

func packNames(names []string, msg []byte, off int, compress map[string]uint16) (int, error) {
	var err error
	for _, name := range names {
		off, err = pack.Name(name, msg, off, compress, false)
		if err != nil {
			return len(msg), err
		}
	}
	return off, nil
}

func packApl(data []APLPrefix, msg []byte, off int) (int, error) {
	var err error
	for i := range data {
		off, err = packAplPrefix(&data[i], msg, off)
		if err != nil {
			return len(msg), err
		}
	}
	return off, nil
}

func packAplPrefix(p *APLPrefix, msg []byte, off int) (int, error) {
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

func unpackApl(s *cryptobyte.String) ([]APLPrefix, error) {
	var prefixes []APLPrefix
	for !s.Empty() {
		prefix, err := unpackAplPrefix(s)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func unpackAplPrefix(s *cryptobyte.String) (APLPrefix, error) {
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

func packIPSECGateway(gatewayAddr net.IP, gatewayString string, msg []byte, off int, gatewayType uint8, compression map[string]uint16, compress bool) (int, error) {
	var err error

	switch gatewayType {
	case IPSECGatewayNone: // do nothing
	case IPSECGatewayIPv4:
		off, err = pack.A(gatewayAddr, msg, off)
	case IPSECGatewayIPv6:
		off, err = pack.AAAA(gatewayAddr, msg, off)
	case IPSECGatewayHost:
		off, err = pack.Name(gatewayString, msg, off, compression, compress)
	}

	return off, err
}

func packTxt(txt []string, msg []byte, off int) (int, error) {
	if len(txt) == 0 {
		if off >= len(msg) {
			return len(msg), pack.ErrBuf
		}
		msg[off] = 0
		return off, nil
	}
	var err error
	for _, s := range txt {
		off, err = pack.TxtString(s, msg, off)
		if err != nil {
			return len(msg), err
		}
	}
	return off, nil
}

func packOctetString(s string, msg []byte, off int) (int, error) {
	if off >= len(msg) || len(s) > 256*4+1 {
		return len(msg), pack.ErrBuf
	}
	for i := 0; i < len(s); i++ {
		if len(msg) <= off {
			return len(msg), pack.ErrBuf
		}
		if s[i] == '\\' {
			i++
			if i == len(s) {
				break
			}
			// check for \DDD
			if ddd.Is(s[i:]) {
				msg[off] = ddd.ToByte(s[i:])
				i += 2
			} else {
				msg[off] = s[i]
			}
		} else {
			msg[off] = s[i]
		}
		off++
	}
	return off, nil
}

func unpackTxt(s *cryptobyte.String) ([]string, error) {
	var strs []string
	for !s.Empty() {
		str, err := unpack.String(s)
		if err != nil {
			return strs, err
		}
		strs = append(strs, str)
	}
	return strs, nil
}
