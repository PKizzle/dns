package pack

import (
	"encoding/binary"
	"net"

	"codeberg.org/miekg/dns/internal/ddd"
)

const maxCompressionOffset = 2 << 13 // We have 14 bits for the compression pointer

// maybe this should all moved to cryptobyte as well...
// near future direction is clear all pack helpers should be here, not in msg_helpers.go

func Uint8(i uint8, msg []byte, off int) (off1 int, err error) {
	if off+1 > len(msg) {
		return len(msg), &Error{"overflow uint8"}
	}
	msg[off] = i
	return off + 1, nil
}

func Uint16(i uint16, msg []byte, off int) (off1 int, err error) {
	if off+2 > len(msg) {
		return len(msg), &Error{"overflow uint16"}
	}
	binary.BigEndian.PutUint16(msg[off:], i)
	return off + 2, nil
}

func Uint32(i uint32, msg []byte, off int) (off1 int, err error) {
	if off+4 > len(msg) {
		return len(msg), &Error{"overflow uint32"}
	}
	binary.BigEndian.PutUint32(msg[off:], i)
	return off + 4, nil
}

func Uint48(i uint64, msg []byte, off int) (off1 int, err error) {
	if off+6 > len(msg) {
		return len(msg), &Error{"overflow uint64 as uint48"}
	}
	msg[off] = byte(i >> 40)
	msg[off+1] = byte(i >> 32)
	msg[off+2] = byte(i >> 24)
	msg[off+3] = byte(i >> 16)
	msg[off+4] = byte(i >> 8)
	msg[off+5] = byte(i)
	off += 6
	return off, nil
}

func Uint64(i uint64, msg []byte, off int) (off1 int, err error) {
	if off+8 > len(msg) {
		return len(msg), &Error{"overflow uint64"}
	}
	binary.BigEndian.PutUint64(msg[off:], i)
	off += 8
	return off, nil
}

// StringAny packs a string as-is, no decoding or lenght bytes are written.
func StringAny(s string, msg []byte, off int) (int, error) {
	if off+len(s) > len(msg) {
		return len(msg), &Error{"overflow string anything"}
	}
	copy(msg[off:off+len(s)], s)
	off += len(s)
	return off, nil
}

func String(s string, msg []byte, off int) (int, error) {
	off, err := TxtString(s, msg, off)
	if err != nil {
		return len(msg), err
	}
	return off, nil
}

func TxtString(s string, msg []byte, off int) (int, error) {
	lenByteoff := off
	if off >= len(msg) || len(s) > 256*4+1 /* If all \DDD */ {
		return len(msg), &Error{"buffer size too small"}
	}
	off++
	for i := 0; i < len(s); i++ {
		if len(msg) <= off {
			return off, &Error{"buffer size too small"}
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
	l := off - lenByteoff - 1
	if l > 255 {
		return len(msg), &Error{"string exceeded 255 bytes in txt"}
	}
	msg[lenByteoff] = byte(l)
	return off, nil
}

func A(a net.IP, msg []byte, off int) (int, error) {
	switch len(a) {
	case net.IPv4len, net.IPv6len:
		// It must be a slice of 4, even if it is 16, we encode only the first 4
		if off+net.IPv4len > len(msg) {
			return len(msg), &Error{"overflow a"}
		}

		copy(msg[off:], a.To4())
		off += net.IPv4len
	default:
		return len(msg), &Error{"overflow a"}
	}
	return off, nil
}

func AAAA(aaaa net.IP, msg []byte, off int) (int, error) {
	switch len(aaaa) {
	case net.IPv6len:
		if off+net.IPv6len > len(msg) {
			return len(msg), &Error{"overflow aaaa"}
		}

		copy(msg[off:], aaaa)
		off += net.IPv6len
	default:
		return len(msg), &Error{"overflow aaaa"}
	}
	return off, nil
}

func Name(s string, msg []byte, off int, compression map[string]uint16, compress bool) (off1 int, err error) {
	// XXX: A logical copy of this function exists in dnsutil.IsName and should be kept in sync with this function.

	ls := len(s)

	// Each dot ends a segment of the name. We trade each dot byte for a length byte.
	// Except for escaped dots (\.), which are normal dots. There is also a trailing zero.

	// Compression
	pointer := ^uint16(0)

	// Emit sequence of counted strings, chopping at dots.
	var (
		begin     int
		compBegin int
		compOff   int
		bs        []byte
		wasDot    bool
	)
loop:
	for i := 0; i < ls; i++ {
		var c byte
		if bs == nil {
			c = s[i]
		} else {
			c = bs[i]
		}

		switch c {
		case '\\':
			if off+1 > len(msg) {
				return len(msg), &Error{"buffer size too small"}
			}

			if bs == nil {
				bs = []byte(s)
			}

			// check for \DDD
			if ddd.Is(bs[i+1:]) {
				bs[i] = ddd.ToByte(bs[i+1:])
				copy(bs[i+1:ls-3], bs[i+4:])
				ls -= 3
				compOff += 3
			} else {
				copy(bs[i:ls-1], bs[i+1:])
				ls--
				compOff++
			}

			wasDot = false
		case '.':
			if i == 0 && len(s) > 1 {
				// leading dots are not legal except for the root zone
				return len(msg), &Error{"bad name: " + string(s)}
			}

			if wasDot {
				// two dots back to back is not legal
				return len(msg), &Error{"bad name: " + string(s)}
			}
			wasDot = true

			labelLen := i - begin
			if labelLen >= 1<<6 { // top two bits of length must be clear
				return len(msg), &Error{"bad label type"}
			}

			// off can already (we're in a loop) be bigger than len(msg)
			// this happens when a name isn't fully qualified
			if off+1+labelLen > len(msg) {
				return len(msg), &Error{"buffer size too small"}
			}

			// Don't try to compress '.'
			// We should only compress when compress is true, but we should also still pick
			// up names that can be used for *future* compression(s).
			if compression != nil && !isRootLabel(s, bs, begin, ls) {
				if p, ok := compression[s[compBegin:]]; ok {
					// The first hit is the longest matching dname
					// keep the pointer offset we get back and store
					// the offset of the current name, because that's
					// where we need to insert the pointer later

					// If compress is true, we're allowed to compress this dname
					if compress {
						pointer = p // Where to point to
						break loop
					}
				} else if off < maxCompressionOffset {
					// Only offsets smaller than maxCompressionOffset can be used.
					compression[s[compBegin:]] = uint16(off)
				}
			}

			// The following is covered by the length check above.
			msg[off] = byte(labelLen)

			if bs == nil {
				copy(msg[off+1:], s[begin:i])
			} else {
				copy(msg[off+1:], bs[begin:i])
			}
			off += 1 + labelLen

			begin = i + 1
			compBegin = begin + compOff
		default:
			wasDot = false
		}
	}

	// Root label is special
	if isRootLabel(s, bs, 0, ls) {
		return off, nil
	}

	if !wasDot {
		return len(msg), &Error{"name must be fully qualified: " + string(s)}
	}

	// If we did compression and we find something add the pointer here
	if pointer != ^uint16(0) {
		// We have two bytes (14 bits) to put the pointer in
		binary.BigEndian.PutUint16(msg[off:], 0xC000|pointer)
		return off + 2, nil
	}

	if off < len(msg) {
		msg[off] = 0
	}

	return off + 1, nil
}

// isRootLabel returns whether s or bs, from off to end, is the root label ".".
// If bs is nil, s will be checked, otherwise bs will be checked.
func isRootLabel(s string, bs []byte, off, end int) bool {
	if bs == nil {
		return s[off:end] == "."
	}

	return end-off == 1 && bs[off] == '.'
}
