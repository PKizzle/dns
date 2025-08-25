package unpack

import (
	"errors"
	"net"
	"strings"

	"codeberg.org/miekg/dns/internal/ddd"
	"golang.org/x/crypto/cryptobyte"
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
