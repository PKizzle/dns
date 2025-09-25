package svcb

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns/internal/ddd"
)

func Parse(p Pair, b, o string) error {
	switch x := p.(type) {
	case *MANDATORY:
		return x.parse(b)
	case *ALPN:
		return x.parse(b)
	case *NODEFAULTALPN:
		return x.parse(b)
	case *PORT:
		return x.parse(b)
	case *IPV4HINT:
		return x.parse(b)
	case *ECHCONFIG:
		return x.parse(b)
	case *IPV6HINT:
		return x.parse(b)
	case *DOHPATH:
		return x.parse(b)
	case *OHTTP:
		return x.parse(b)
	case *LOCAL:
		return x.parse(b)
	}
	return fmt.Errorf("dns: no svcb parse defined")
}

// should all be generated, allthough the difference are huge...

func (s *MANDATORY) parse(b string) error {
	keys := make([]uint16, 0, strings.Count(b, ",")+1)
	for len(b) > 0 {
		var key string
		key, b, _ = strings.Cut(b, ",")
		keys = append(keys, StringToKey(key))
	}
	s.Key = keys
	return nil
}

func (s *ALPN) parse(b string) error {
	if len(b) == 0 {
		s.Alpn = []string{}
		return nil
	}

	alpn := []string{}
	a := []byte{}
	for p := 0; p < len(b); {
		c, q := ddd.Next(b, p)
		if q == 0 {
			return errors.New("dns: svcbalpn: unterminated escape")
		}
		p += q
		// If we find a comma, we have finished reading an alpn.
		if c == ',' {
			if len(a) == 0 {
				return errors.New("dns: svcbalpn: empty protocol identifier")
			}
			alpn = append(alpn, string(a))
			a = []byte{}
			continue
		}
		// If it's a backslash, we need to handle a comma-separated list.
		if c == '\\' {
			dc, dq := ddd.Next(b, p)
			if dq == 0 {
				return errors.New("dns: svcbalpn: unterminated escape decoding comma-separated list")
			}
			if dc != '\\' && dc != ',' {
				return errors.New("dns: svcbalpn: bad escaped character decoding comma-separated list")
			}
			p += dq
			c = dc
		}
		a = append(a, c)
	}
	// Add the final alpn.
	if len(a) == 0 {
		return errors.New("dns: svcbalpn: last protocol identifier empty")
	}
	s.Alpn = append(alpn, string(a))
	return nil
}

func (*NODEFAULTALPN) parse(b string) error {
	if len(b) != 0 {
		return errors.New("dns: svcbnodefaultalpn: no-default-alpn must have no value")
	}
	return nil
}

func (s *PORT) parse(b string) error {
	port, err := strconv.ParseUint(b, 10, 16)
	if err != nil {
		return errors.New("dns: svcbport: port out of range")
	}
	s.Port = uint16(port)
	return nil
}

func (s *IPV4HINT) parse(b string) error {
	if len(b) == 0 {
		return errors.New("dns: svcbipv4hint: empty hint")
	}
	if strings.Contains(b, ":") {
		return errors.New("dns: svcbipv4hint: expected ipv4, got ipv6")
	}

	hint := make([]net.IP, 0, strings.Count(b, ",")+1)
	for len(b) > 0 {
		var e string
		e, b, _ = strings.Cut(b, ",")
		ip := net.ParseIP(e).To4()
		if ip == nil {
			return errors.New("dns: svcbipv4hint: bad ip")
		}
		hint = append(hint, ip)
	}
	s.Hint = hint
	return nil
}

func (s *ECHCONFIG) parse(b string) error {
	x, err := fromBase64([]byte(b)) // todo, move frombase64 somewhere...
	if err != nil {
		return errors.New("dns: svcbech: bad base64 ech")
	}
	s.ECH = x
	return nil
}

func (s *IPV6HINT) parse(b string) error {
	if len(b) == 0 {
		return errors.New("dns: svcbipv6hint: empty hint")
	}

	hint := make([]net.IP, 0, strings.Count(b, ",")+1)
	for len(b) > 0 {
		var e string
		e, b, _ = strings.Cut(b, ",")
		ip := net.ParseIP(e)
		if ip == nil {
			return errors.New("dns: svcbipv6hint: bad ip")
		}
		if ip.To4() != nil {
			return errors.New("dns: svcbipv6hint: expected ipv6, got ipv4-mapped-ipv6")
		}
		hint = append(hint, ip)
	}
	s.Hint = hint
	return nil
}

func (s *DOHPATH) parse(b string) error {
	template, err := stringToPair(b)
	if err != nil {
		return fmt.Errorf("dns: svcbdohpath: %w", err)
	}
	s.Template = string(template)
	return nil
}

func (*OHTTP) parse(b string) error {
	if len(b) != 0 {
		return errors.New("dns: svcbotthp: svcbotthp must have no value")
	}
	return nil
}

func (s *LOCAL) parse(b string) error {
	data, err := stringToPair(b)
	if err != nil {
		return fmt.Errorf("dns: svcblocal: svcb private/experimental key %w", err)
	}
	s.Data = data
	return nil
}
