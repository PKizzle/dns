package pack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"codeberg.org/miekg/dns/internal/ddd"
)

// maybe this should all moved to cryptobyte as well...
// near future direction is clear all pack helpers should be here, not in msg_helpers.go

func Uint8(i uint8, msg []byte, off int) (off1 int, err error) {
	if off+1 > len(msg) {
		return len(msg), fmt.Errorf("dns: overflow packing uint8")
	}
	msg[off] = i
	return off + 1, nil
}

func Uint16(i uint16, msg []byte, off int) (off1 int, err error) {
	if off+2 > len(msg) {
		return len(msg), fmt.Errorf("dns: overflow packing uint16")
	}
	binary.BigEndian.PutUint16(msg[off:], i)
	return off + 2, nil
}

func Uint32(i uint32, msg []byte, off int) (off1 int, err error) {
	if off+4 > len(msg) {
		return len(msg), fmt.Errorf("dns: overflow packing uint32")
	}
	binary.BigEndian.PutUint32(msg[off:], i)
	return off + 4, nil
}

func Uint48(i uint64, msg []byte, off int) (off1 int, err error) {
	if off+6 > len(msg) {
		return len(msg), fmt.Errorf("overflow packing uint64 as uint48")
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
		return len(msg), fmt.Errorf("dns: overflow packing uint64")
	}
	binary.BigEndian.PutUint64(msg[off:], i)
	off += 8
	return off, nil
}

// StringAny packs a string as-is, no decoding or lenght bytes are written.
func StringAny(s string, msg []byte, off int) (int, error) {
	if off+len(s) > len(msg) {
		return len(msg), fmt.Errorf("dns: overflow packing string anything")
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
		return len(msg), errors.New("dns: buffer size too small")
	}
	off++
	for i := 0; i < len(s); i++ {
		if len(msg) <= off {
			return off, errors.New("dns: buffer size too small")
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
		return len(msg), errors.New("dns: string exceeded 255 bytes in txt")
	}
	msg[lenByteoff] = byte(l)
	return off, nil
}

func A(a net.IP, msg []byte, off int) (int, error) {
	switch len(a) {
	case net.IPv4len, net.IPv6len:
		// It must be a slice of 4, even if it is 16, we encode only the first 4
		if off+net.IPv4len > len(msg) {
			return len(msg), fmt.Errorf("dns: overflow packing a")
		}

		copy(msg[off:], a.To4())
		off += net.IPv4len
	default:
		return len(msg), fmt.Errorf("dns: overflow packing a")
	}
	return off, nil
}

func AAAA(aaaa net.IP, msg []byte, off int) (int, error) {
	switch len(aaaa) {
	case net.IPv6len:
		if off+net.IPv6len > len(msg) {
			return len(msg), fmt.Errorf("dns: overflow packing aaaa")
		}

		copy(msg[off:], aaaa)
		off += net.IPv6len
	default:
		return len(msg), fmt.Errorf("dns: overflow packing aaaa")
	}
	return off, nil
}
