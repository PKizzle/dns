package unpack

import (
	"errors"
	"net"

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
