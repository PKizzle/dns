package deleg

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns/internal/ddd"
	"codeberg.org/miekg/dns/internal/pack"
	"codeberg.org/miekg/dns/internal/unpack"
	"golang.org/x/crypto/cryptobyte"
)

// should all be generated...

// _pack converts an info to wire-format.
func _pack(i Info, msg []byte, off int) (int, error) {
	switch x := i.(type) {
	case *SERVERIPV4:
		return x.pack(msg, off)
	case *SERVERIPV6:
		return x.pack(msg, off)
	}
	return 0, fmt.Errorf("dns: no deleg pack defined")
}

// unpack converts wire-format to an info.
func _unpack(i Info, data *cryptobyte.String) error {
	switch x := i.(type) {
	case *SERVERIPV4:
		return x.unpack(data)
	case *SERVERIPV6:
		return x.unpack(data)
	}
	return fmt.Errorf("dns: no deleg unpack defined")
}

func (s *SERVERIPV4) pack(msg []byte, off int) (int, error) {
	off, err := packTLV(s, msg, off)
	if err != nil {
		return off, err
	}
	for _, ip := range s.IPs {
		off, err = pack.A(ip, msg, off)
		if err != nil {
			return off, err
		}
	}
	return off, nil
}

func (s *SERVERIPV4) unpack(sc *cryptobyte.String) error {
	for !sc.Empty() {
		ip, err := unpack.A(sc)
		if err != nil {
			return errors.New("dns: delegserverip4: ipv4 address byte array length is not a multiple of 4")
		}
		s.IPs = append(s.IPs, ip)
	}
	return nil
}

func (s *SERVERIPV6) pack(msg []byte, off int) (int, error) {
	off, err := packTLV(s, msg, off)
	if err != nil {
		return off, err
	}
	for _, ip := range s.IPs {
		off, err = pack.AAAA(ip, msg, off)
		if err != nil {
			return off, err
		}
	}
	return off, nil
}

func (s *SERVERIPV6) unpack(sc *cryptobyte.String) error {
	for !sc.Empty() {
		ip, err := unpack.AAAA(sc)
		if err != nil {
			return errors.New("dns: delegserverip6: expected ipv6, got ipv4")
		}
		s.IPs = append(s.IPs, ip)
	}
	return nil
}

func packTLV(p Info, msg []byte, off int) (off1 int, err error) {
	key := InfoToKey(p)
	length := uint16(p.Len()) - tlv // now here we do the rdata length, not the 4 octets we encoding here
	off, err = pack.Uint16(key, msg, off)
	if err != nil {
		return len(msg), fmt.Errorf("dns: overflow packing DELEG")
	}
	off, err = pack.Uint16(length, msg, off)
	if err != nil {
		return len(msg), fmt.Errorf("dns: overflow packing DELEG")
	}
	return off, err
}

// TODO(miek): identical to svcb's one

// infoToString converts the value of an SVCB parameter into a DNS presentation-format string.
func infoToString(s []byte) string {
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

// stringToInfo parses a DNS presentation-format string into an SVCB parameter value.
func stringToInfo(b string) ([]byte, error) {
	data := make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		if b[i] != '\\' {
			data = append(data, b[i])
			i++
			continue
		}
		if i+1 == len(b) {
			return nil, errors.New("dns: escape unterminated")
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
			return nil, errors.New("dns: bad escaped octet")
		} else {
			data = append(data, b[i+1])
			i += 2
		}
	}
	return data, nil
}
