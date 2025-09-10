package deleg

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

func Parse(i Info, b string) error {
	switch x := i.(type) {
	case *SERVERIP6:
		return x.parse(b)
	case *SERVERIP4:
		return x.parse(b)
	}
	return fmt.Errorf("dns: no deleg parse defined")
}

// should all be generated, allthough the difference are huge...

func (s *SERVERIP4) parse(b string) error {
	if len(b) == 0 {
		return errors.New("dns: delegserverip4: empty ips")
	}
	if strings.Contains(b, ":") {
		return errors.New("dns: delegserverip4: expected ipv4, got ipv6")
	}

	ips := make([]net.IP, 0, strings.Count(b, ",")+1)
	for len(b) > 0 {
		var e string
		e, b, _ = strings.Cut(b, ",")
		ip := net.ParseIP(e).To4()
		if ip == nil {
			return errors.New("dns: delegserverip4: bad ip")
		}
		ips = append(ips, ip)
	}
	s.IPs = ips
	return nil
}

func (s *SERVERIP6) parse(b string) error {
	if len(b) == 0 {
		return errors.New("dns: delegserverip6: empty ips")
	}

	ips := make([]net.IP, 0, strings.Count(b, ",")+1)
	for len(b) > 0 {
		var e string
		e, b, _ = strings.Cut(b, ",")
		ip := net.ParseIP(e)
		if ip == nil {
			return errors.New("dns: delegserverip6: bad ip")
		}
		if ip.To4() != nil {
			return errors.New("dns: delegserverip6: expected ipv6, got ipv4-mapped-ipv6")
		}
		ips = append(ips, ip)
	}
	s.IPs = ips
	return nil
}
