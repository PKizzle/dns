package svcb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns/internal/ddd"
	"golang.org/x/crypto/cryptobyte"
)

// should all be generated

func Pack(p Pair, msg []byte, off int) (int, error) {
	switch x := p.(type) {
	case *MANDATORY:
		return x.pack(msg, off)
	case *ALPN:
		return x.pack(msg, off)
	case *NODEFAULTALPN:
		return x.pack(msg, off)
	case *PORT:
		return x.pack(msg, off)
	case *IPV4HINT:
		return x.pack(msg, off)
	case *ECHCONFIG:
		return x.pack(msg, off)
	case *IPV6HINT:
		return x.pack(msg, off)
	case *DOHPATH:
		return x.pack(msg, off)
	case *OHTTP:
		return x.pack(msg, off)
	}
	return 0, fmt.Errorf("dns: no pair pack defined")
}

func Unpack(p Pair, data []byte) error {
	switch x := p.(type) {
	case *MANDATORY:
		return x.unpack(data)
	case *ALPN:
		return x.unpack(data)
	case *NODEFAULTALPN:
		return x.unpack(data)
	case *PORT:
		return x.unpack(data)
	case *IPV4HINT:
		return x.unpack(data)
	case *ECHCONFIG:
		return x.unpack(data)
	case *IPV6HINT:
		return x.unpack(data)
	case *DOHPATH:
		return x.unpack(data)
	case *OHTTP:
	}
	return fmt.Errorf("dns: no pair unpack defined")
}

func (s *MANDATORY) pack() ([]byte, error) {
	keys := slices.Clone(s.Key)
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	b := make([]byte, s.Len())
	for i, e := range keys {
		binary.BigEndian.PutUint16(b[2*i:], e)
	}
	return b, nil
}

func (s *MANDATORY) unpack(b []byte) error {
	if len(b)%2 != 0 {
		return errors.New("dns: svcbmandatory: value length is not a multiple of 2")
	}
	keys := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		// We assume strictly increasing order.
		keys = append(keys, binary.BigEndian.Uint16(b[i:]))
	}
	s.Key = keys
	return nil
}

func (s *ALPN) pack() ([]byte, error) {
	// Liberally estimate the size of an alpn as 10 octets
	b := make([]byte, 0, 10*len(s.Alpn))
	for _, e := range s.Alpn {
		if e == "" {
			return nil, errors.New("dns: svcbalpn: empty alpn-id")
		}
		if len(e) > 255 {
			return nil, errors.New("dns: svcbalpn: alpn-id too long")
		}
		b = append(b, byte(len(e)))
		b = append(b, e...)
	}
	return b, nil
}

func (s *ALPN) unpack(b []byte) error {
	sc := cryptobyte.String(b)
	var alpn []string
	for !sc.Empty() {
		var data cryptobyte.String
		if !sc.ReadUint8LengthPrefixed(&data) {
			return ErrUnpackOverflow
		}
		alpn = append(alpn, string(data))
	}
	s.Alpn = alpn
	return nil
}

func (*NODEFAULTALPN) pack() ([]byte, error) { return []byte{}, nil }

func (*NODEFAULTALPN) unpack(b []byte) error {
	if len(b) != 0 {
		return errors.New("dns: svcbnodefaultalpn: no-default-alpn must have no value")
	}
	return nil
}

func (s *PORT) unpack(b []byte) error {
	if len(b) != 2 {
		return errors.New("dns: svcbport: port length is not exactly 2 octets")
	}
	s.Port = binary.BigEndian.Uint16(b)
	return nil
}

func (s *PORT) pack() ([]byte, error) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, s.Port)
	return b, nil
}

func (s *IPV4HINT) pack() ([]byte, error) {
	b := make([]byte, 0, 4*len(s.Hint))
	for _, e := range s.Hint {
		x := e.To4()
		if x == nil {
			return nil, errors.New("dns: svcbipv4hint: expected ipv4, hint is ipv6")
		}
		b = append(b, x...)
	}
	return b, nil
}

func (s *IPV4HINT) unpack(b []byte) error {
	if len(b) == 0 || len(b)%4 != 0 {
		return errors.New("dns: svcbipv4hint: ipv4 address byte array length is not a multiple of 4")
	}
	b = slices.Clone(b)
	x := make([]net.IP, 0, len(b)/4)
	for i := 0; i < len(b); i += 4 {
		x = append(x, net.IP(b[i:i+4]))
	}
	s.Hint = x
	return nil
}

func (s *ECHCONFIG) pack() ([]byte, error) {
	return slices.Clone(s.ECH), nil
}

func (s *IPV6HINT) pack() ([]byte, error) {
	b := make([]byte, 0, 16*len(s.Hint))
	for _, e := range s.Hint {
		if len(e) != net.IPv6len || e.To4() != nil {
			return nil, errors.New("dns: svcbipv6hint: expected ipv6, hint is ipv4")
		}
		b = append(b, e...)
	}
	return b, nil
}

func (s *IPV6HINT) unpack(b []byte) error {
	if len(b) == 0 || len(b)%16 != 0 {
		return errors.New("dns: svcbipv6hint: ipv6 address byte array length not a multiple of 16")
	}
	b = slices.Clone(b)
	x := make([]net.IP, 0, len(b)/16)
	for i := 0; i < len(b); i += 16 {
		ip := net.IP(b[i : i+16])
		if ip.To4() != nil {
			return errors.New("dns: svcbipv6hint: expected ipv6, got ipv4")
		}
		x = append(x, ip)
	}
	s.Hint = x
	return nil
}

func (s *DOHPATH) pack() ([]byte, error) { return []byte(s.Template), nil }

func (s *DOHPATH) unpack(b []byte) error {
	s.Template = string(b)
	return nil
}

func (*OHTTP) pack() ([]byte, error) { return []byte{}, nil }

func (*OHTTP) unpack(b []byte) error {
	if len(b) != 0 {
		return errors.New("dns: svcbotthp: svcbotthp must have no value")
	}
	return nil
}

func (s *LOCAL) pack() ([]byte, error) { return slices.Clone(s.Data), nil }

func (s *LOCAL) unpack(b []byte) error {
	s.Data = slices.Clone(b)
	return nil
}

// pairToString converts the value of an SVCB parameter into a DNS presentation-format string.
func pairToString(s []byte) string {
	var str strings.Builder
	str.Grow(4 * len(s))
	for _, e := range s {
		if ' ' <= e && e <= '~' {
			switch e {
			case '"', ';', ' ', '\\':
				str.WriteByte('\\')
				str.WriteByte(e)
			default:
				str.WriteByte(e)
			}
		} else {
			str.WriteString(ddd.Escape(e))
		}
	}
	return str.String()
}

// stringToPair parses a DNS presentation-format string into an SVCB parameter value.
func stringToPair(b string) ([]byte, error) {
	data := make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		if b[i] != '\\' {
			data = append(data, b[i])
			i++
			continue
		}
		if i+1 == len(b) {
			return nil, errors.New("escape unterminated")
		}
		if ddd.IsDigit(b[i+1]) {
			if i+3 < len(b) && ddd.IsDigit(b[i+2]) && ddd.IsDigit(b[i+3]) {
				a, err := strconv.ParseUint(b[i+1:i+4], 10, 8)
				if err == nil {
					i += 4
					data = append(data, byte(a))
					continue
				}
			}
			return nil, errors.New("bad escaped octet")
		} else {
			data = append(data, b[i+1])
			i += 2
		}
	}
	return data, nil
}
