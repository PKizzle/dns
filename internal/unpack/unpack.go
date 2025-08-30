package unpack

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"codeberg.org/miekg/dns/internal/ddd"
	"golang.org/x/crypto/cryptobyte"
)

const (
	maxNameWireOctets = 255 // See RFC 1035 section 2.3.4

	// This is the maximum length of a domain name in presentation format. The
	// maximum wire length of a domain name is 255 octets (see above), with the
	// maximum label length being 63. The wire format requires one extra byte over
	// the presentation format, reducing the number of octets by 1. Each label in
	// the name will be separated by a single period, with each octet in the label
	// expanding to at most 4 bytes (\DDD). If all other labels are of the maximum
	// length, then the final label can only be 61 octets long to not exceed the
	// maximum allowed wire length.
	maxNamePresentationLength = 61*4 + 1 + 63*4 + 1 + 63*4 + 1 + 63*4 + 1
)

func A(s *cryptobyte.String) (net.IP, error) {
	ip := make(net.IP, net.IPv4len)
	if !s.CopyBytes(ip) {
		return nil, errors.New("dns: overflow unpacking a")
	}
	return ip, nil
}

func AAAA(s *cryptobyte.String) (net.IP, error) {
	ip := make(net.IP, net.IPv6len)
	if !s.CopyBytes(ip) {
		return nil, errors.New("dns: overflow unpacking aaaa")
	}
	return ip, nil
}

func StringAny(s *cryptobyte.String, len int) (string, error) {
	var b []byte
	if !s.ReadBytes(&b, len) {
		return "", errors.New("dns: overflow unpacking string anything")
	}
	return string(b), nil
}

func String(s *cryptobyte.String) (string, error) {
	var txt cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&txt) {
		return "", errors.New("dns: overflow unpacking string")
	}
	var sb strings.Builder
	consumed := 0
	for i, b := range txt {
		switch {
		case b == '"' || b == '\\':
			if consumed == 0 {
				sb.Grow(len(txt) * 2)
			}
			sb.Write(txt[consumed:i])
			sb.WriteByte('\\')
			sb.WriteByte(b)
			consumed = i + 1
		case b < ' ' || b > '~': // unprintable
			if consumed == 0 {
				sb.Grow(len(txt) * 2)
			}
			sb.Write(txt[consumed:i])
			sb.WriteString(ddd.Escape(b))
			consumed = i + 1
		}
	}
	if consumed == 0 { // no escaping needed
		return string(txt), nil
	}
	sb.Write(txt[consumed:])
	return sb.String(), nil
}

// Name unpacks a domain name.
// In addition to the simple sequences of counted strings above, domain names are allowed to refer to strings elsewhere in the
// packet, to avoid repeating common suffixes when returning many entries in a single domain. The pointers are marked
// by a length byte with the top two bits set. Ignoring those two bits, that byte and the next give a 14 bit offset from into msg
// where we should pick up the trail.
// Note that if we jump elsewhere in the packet, we record the last offset we read from when we found the first pointer,
// which is where the next record or record field will start. We enforce that pointers always point backwards into the message.

// Name unpacks a domain name into a string. It returns the name, the new offset into msg and any error that occurred.
// When an error is encountered, the unpacked name will be discarded and len(msg) will be returned as the offset.
func NameOnlyUsedInDNSSEC(msg []byte, off int) (string, int, error) {
	s := cryptobyte.String(msg[off:])
	name, err := Name(&s, msg)
	if err != nil {
		return "", len(msg), err
	}
	return name, Offset(s, msg), nil
}

// Name unpacks a name in a cryptobyte.String. TODO(miek): fold into the above.
func Name(s *cryptobyte.String, msgBuf []byte) (string, error) {
	name := make([]byte, 0, maxNamePresentationLength) // should we make the cap smaller, and then pay the price for larger names?
	budget := maxNameWireOctets
	var ptrs bool

	// If we never see a pointer, we need to ensure that we advance s to our final position.
	cs := *s

	for {
		var c byte
		if !cs.ReadUint8(&c) {
			return "", fmt.Errorf("dns: overflow unpacking data")
		}
		switch c & 0xC0 {
		case 0x00: // literal string
			var label []byte
			if !cs.ReadBytes(&label, int(c)) {
				return "", fmt.Errorf("dns: overflow unpacking data")
			}
			// If we see a zero-length label (root label), this is the end of the name.
			if len(label) == 0 {
				if !ptrs {
					*s = cs
				}
				if len(name) == 0 {
					return ".", nil
				}
				return string(name), nil
			}
			if budget -= len(label) + 1; budget <= 0 { // +1 for the label separator
				return "", fmt.Errorf("name exceeded max wire-format octets: %s", s)
			}
			for _, b := range label {
				if ddd.ShouldEscape(b) {
					name = append(name, '\\', b)
				} else if b < ' ' || b > '~' {
					name = append(name, ddd.Escape(b)...)
				} else {
					name = append(name, b)
				}
			}
			name = append(name, '.')
		case 0xC0: // pointer
			var c1 byte
			if !cs.ReadUint8(&c1) {
				return "", fmt.Errorf("dns: overflow unpacking data")
			}
			// If this is the first pointer we've seen, we need to advance s to our current position.
			if !ptrs {
				*s = cs
			}
			// The pointer should always point backwards to an earlier part of the message. Technically it could work pointing
			// forwards, but we choose not to support that as RFC 1035 specifically refers to a "prior
			// occurrence".
			off := uint16(c&^0xC0)<<8 | uint16(c1)
			if int(off) >= Offset(cs, msgBuf)-2 {
				return "", fmt.Errorf("dns: pointer not to prior occurrence of name")
			}
			// Jump to the offset in msgBuf. We carry msgBuf around with us solely for this line.
			cs = msgBuf[off:]
			ptrs = true
		default: // 0x80 and 0x40 are reserved
			return "", fmt.Errorf("dns: reserved domain name label type")
		}
	}
}

// Offset reports the offset of data into buf, that is reports off such that
// &data[0] == &buf[off]. It panics if data is not buf[off:].
func Offset(data, buf []byte) int {
	if len(data) > 0 && len(buf) > 0 && &data[len(data)-1] != &buf[len(buf)-1] {
		panic("dns: internal error: cannot compute off")
	}
	return len(buf) - len(data)
}
