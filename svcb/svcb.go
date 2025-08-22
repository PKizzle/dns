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

// Key is the type of the keys used in the SVCB RR.
type Key uint16

// Keys defined in rfc9460
const (
	KeyMandatory Key = iota
	KeyAlpn
	KeyNoDefaultALPN
	KeyPort
	KeyIPv4Hint
	KeyEchConfig
	KeyIPv6Hint
	KeyDohPath // rfc9461 Section 5
	KeyOhttp   // rfc9540 Section 8

	KeyReserved Key = 65535
)

var KeyToString = map[Key]string{
	KeyMandatory:     "mandatory",
	KeyAlpn:          "alpn",
	KeyNoDefaultALPN: "no-default-alpn",
	KeyPort:          "port",
	KeyIPv4Hint:      "ipv4hint",
	KeyEchConfig:     "ech",
	KeyIPv6Hint:      "ipv6hint",
	KeyDohPath:       "dohpath",
	KeyOhttp:         "ohttp",
}

var StringToKey = reverse(KeyToString)

// KeyToPair is a map of constructors for each key type.
var KeyToPair = map[Key]func() Pair{
	KeyMandatory:     func() Pair { return new(MANDATORY) },
	KeyAlpn:          func() Pair { return new(ALPN) },
	KeyNoDefaultALPN: func() Pair { return new(NODEFAULTALPN) },
	KeyPort:          func() Pair { return new(PORT) },
	KeyIPv4Hint:      func() Pair { return new(IPV4HINT) },
	KeyEchConfig:     func() Pair { return new(ECHCONFIG) },
	KeyIPv6Hint:      func() Pair { return new(IPV6HINT) },
	KeyDohPath:       func() Pair { return new(DOHPATH) },
	KeyOhttp:         func() Pair { return new(OHTTP) },
}

// LOCAL ones
/*
	default:
		e := new(LOCAL)
		e.KeyCode = key
		return e
	}
*/

// PairToKey is the opposite of KeyToPair.
func PairToKey(p Pair) Key {
	switch p.(type) {
	case *MANDATORY:
		return KeyMandatory
	case *ALPN:
		return KeyAlpn
	case *NODEFAULTALPN:
		return KeyNoDefaultALPN
	case *PORT:
		return KeyPort
	case *IPV4HINT:
		return KeyIPv4Hint
	case *ECHCONFIG:
		return KeyEchConfig
	case *IPV6HINT:
		return KeyIPv6Hint
	case *DOHPATH:
		return KeyDohPath
	case *OHTTP:
		return KeyOhttp
	}
	return KeyReserved
}

// Pair defines a key=value pair for the SVCB RR type.
// An SVCB RR can have multiple Pairs appended to it.
// The numerical key code is derived from the type.
type Pair interface {
	String() string // String returns the string representation of the value.
	Len() int       // Len returns the length of value in the wire format.
}

// MANDATORY pair adds to required keys that must be interpreted for the RR
// to be functional. If ignored, the whole RRSet must be ignored.
// "port" and "no-default-alpn" are mandatory by default if present,
// so they shouldn't be included here.
//
// It is incumbent upon the user of this library to reject the RRSet if
// or avoid constructing such an RRSet that:
// - "mandatory" is included as one of the keys of mandatory
// - no key is listed multiple times in mandatory
// - all keys listed in mandatory are present
// - escape sequences are not used in mandatory
// - mandatory, when present, lists at least one key
//
// Basic use pattern for creating a mandatory option:
//
//	s := &dns.SVCB{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeSVCB, Class: dns.ClassINET}}
//	e := new(dns.MANDATORY)
//	e.Code = []uint16{dns.SVCB_ALPN}
//	s.Value = append(s.Value, e)
//	t := new(dns.ALPN)
//	t.Alpn = []string{"xmpp-client"}
//	s.Value = append(s.Value, t)
type MANDATORY struct {
	Code []Key
}

func (s *MANDATORY) String() string {
	str := make([]string, len(s.Code))
	for i, e := range s.Code {
		str[i] = KeyToString[e]
	}
	return strings.Join(str, ",")
}

func (s *MANDATORY) pack() ([]byte, error) {
	codes := slices.Clone(s.Code)
	sort.Slice(codes, func(i, j int) bool {
		return codes[i] < codes[j]
	})
	b := make([]byte, 2*len(codes))
	for i, e := range codes {
		binary.BigEndian.PutUint16(b[2*i:], uint16(e))
	}
	return b, nil
}

func (s *MANDATORY) unpack(b []byte) error {
	if len(b)%2 != 0 {
		return errors.New("dns: svcbmandatory: value length is not a multiple of 2")
	}
	codes := make([]Key, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		// We assume strictly increasing order.
		codes = append(codes, Key(binary.BigEndian.Uint16(b[i:])))
	}
	s.Code = codes
	return nil
}

func (s *MANDATORY) parse(b string) error {
	codes := make([]Key, 0, strings.Count(b, ",")+1)
	for len(b) > 0 {
		var key string
		key, b, _ = strings.Cut(b, ",")
		codes = append(codes, svcbStringToKey(key))
	}
	s.Code = codes
	return nil
}

func (s *MANDATORY) Len() int {
	return 2 * len(s.Code)
}

// ALPN pair is used to list supported connection protocols.
// The user of this library must ensure that at least one protocol is listed when alpn is present.
// Protocol IDs can be found at:
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
// Basic use pattern for creating an alpn option:
//
//	h := new(dns.HTTPS)
//	h.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET}
//	e := new(dns.ALPN)
//	e.Alpn = []string{"h2", "http/1.1"}
//	h.Value = append(h.Value, e)
type ALPN struct {
	Alpn []string
}

func (s *ALPN) String() string {
	// An ALPN value is a comma-separated list of values, each of which can be
	// an arbitrary binary value. In order to allow parsing, the comma and
	// backslash characters are themselves escaped.
	//
	// However, this escaping is done in addition to the normal escaping which
	// happens in zone files, meaning that these values must be
	// double-escaped. This looks terrible, so if you see a never-ending
	// sequence of backslash in a zone file this may be why.
	//
	// https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-08#appendix-A.1
	var str strings.Builder
	for i, alpn := range s.Alpn {
		// 4*len(alpn) is the worst case where we escape every character in the alpn as \123, plus 1 byte for the ',' separating the alpn from others
		str.Grow(4*len(alpn) + 1)
		if i > 0 {
			str.WriteByte(',')
		}
		for j := 0; j < len(alpn); j++ {
			e := alpn[j]
			if ' ' > e || e > '~' {
				str.WriteString(ddd.Escape(e))
				continue
			}
			switch e {
			// We escape a few characters which may confuse humans or parsers.
			case '"', ';', ' ':
				str.WriteByte('\\')
				str.WriteByte(e)
			// The comma and backslash characters themselves must be
			// doubly-escaped. We use `\\` for the first backslash and
			// the escaped numeric value for the other value. We especially
			// don't want a comma in the output.
			case ',':
				str.WriteString(`\\\044`)
			case '\\':
				str.WriteString(`\\\092`)
			default:
				str.WriteByte(e)
			}
		}
	}
	return str.String()
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

func (s *ALPN) parse(b string) error {
	if len(b) == 0 {
		s.Alpn = []string{}
		return nil
	}

	alpn := []string{}
	a := []byte{}
	for p := 0; p < len(b); {
		c, q := nextByte(b, p)
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
			dc, dq := nextByte(b, p)
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

func (s *ALPN) Len() int {
	var l int
	for _, e := range s.Alpn {
		l += 1 + len(e)
	}
	return l
}

// NODEFAULTALPN pair signifies no support for default connection protocols.
// Should be used in conjunction with alpn.
// Basic use pattern for creating a no-default-alpn option:
//
//	s := &dns.SVCB{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeSVCB, Class: dns.ClassINET}}
//	t := new(dns.ALPN)
//	t.Alpn = []string{"xmpp-client"}
//	s.Value = append(s.Value, t)
//	e := new(dns.NODEFAULTALPN)
//	s.Value = append(s.Value, e)
type NODEFAULTALPN struct{}

func (*NODEFAULTALPN) String() string { return "" }
func (*NODEFAULTALPN) Len() int       { return 0 }

func (*NODEFAULTALPN) unpack(b []byte) error {
	if len(b) != 0 {
		return errors.New("dns: svcbnodefaultalpn: no-default-alpn must have no value")
	}
	return nil
}

func (*NODEFAULTALPN) parse(b string) error {
	if b != "" {
		return errors.New("dns: svcbnodefaultalpn: no-default-alpn must have no value")
	}
	return nil
}

// PORT pair defines the port for connection.
// Basic use pattern for creating a port option:
//
//	s := &dns.SVCB{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeSVCB, Class: dns.ClassINET}}
//	e := new(dns.PORT)
//	e.Port = 80
//	s.Value = append(s.Value, e)
type PORT struct {
	Port uint16
}

func (*PORT) Len() int         { return 2 }
func (s *PORT) String() string { return strconv.FormatUint(uint64(s.Port), 10) }

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

func (s *PORT) parse(b string) error {
	port, err := strconv.ParseUint(b, 10, 16)
	if err != nil {
		return errors.New("dns: svcbport: port out of range")
	}
	s.Port = uint16(port)
	return nil
}

// IPV4HINT pair suggests an IPv4 address which may be used to open connections
// if A and AAAA record responses for SVCB's Target domain haven't been received.
// In that case, optionally, A and AAAA requests can be made, after which the connection
// to the hinted IP address may be terminated and a new connection may be opened.
// Basic use pattern for creating an ipv4hint option:
//
//		h := new(dns.HTTPS)
//		h.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET}
//		e := new(dns.IPV4HINT)
//		e.Hint = []net.IP{net.IPv4(1,1,1,1).To4()}
//
//	 Or
//
//		e.Hint = []net.IP{net.ParseIP("1.1.1.1").To4()}
//		h.Value = append(h.Value, e)
type IPV4HINT struct {
	Hint []net.IP
}

func (s *IPV4HINT) Len() int { return 4 * len(s.Hint) }

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

func (s *IPV4HINT) String() string {
	str := make([]string, len(s.Hint))
	for i, e := range s.Hint {
		x := e.To4()
		if x == nil {
			return "<nil>"
		}
		str[i] = x.String()
	}
	return strings.Join(str, ",")
}

func (s *IPV4HINT) parse(b string) error {
	if b == "" {
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

// ECHCONFIG pair contains the ECHConfig structure defined in draft-ietf-tls-esni [RFC xxxx].
// Basic use pattern for creating an ech option:
//
//	h := new(dns.HTTPS)
//	h.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET}
//	e := new(dns.ECHCONFIG)
//	e.ECH = []byte{0xfe, 0x08, ...}
//	h.Value = append(h.Value, e)
type ECHCONFIG struct {
	ECH []byte // Specifically ECHConfigList including the redundant length prefix
}

func (s *ECHCONFIG) String() string { return toBase64(s.ECH) }
func (s *ECHCONFIG) Len() int       { return len(s.ECH) }

func (s *ECHCONFIG) pack() ([]byte, error) {
	return slices.Clone(s.ECH), nil
}

func (s *ECHCONFIG) parse(b string) error {
	x, err := fromBase64([]byte(b)) // tODO
	if err != nil {
		return errors.New("dns: svcbech: bad base64 ech")
	}
	s.ECH = x
	return nil
}

// IPV6HINT pair suggests an IPv6 address which may be used to open connections
// if A and AAAA record responses for SVCB's Target domain haven't been received.
// In that case, optionally, A and AAAA requests can be made, after which the
// connection to the hinted IP address may be terminated and a new connection may be opened.
// Basic use pattern for creating an ipv6hint option:
//
//	h := new(dns.HTTPS)
//	h.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET}
//	e := new(dns.IPV6HINT)
//	e.Hint = []net.IP{net.ParseIP("2001:db8::1")}
//	h.Value = append(h.Value, e)
type IPV6HINT struct {
	Hint []net.IP
}

func (s *IPV6HINT) Len() int { return 16 * len(s.Hint) }

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

func (s *IPV6HINT) String() string {
	str := make([]string, len(s.Hint))
	for i, e := range s.Hint {
		if x := e.To4(); x != nil {
			return "<nil>"
		}
		str[i] = e.String()
	}
	return strings.Join(str, ",")
}

func (s *IPV6HINT) parse(b string) error {
	if b == "" {
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

// DOHPATH pair is used to indicate the URI template that the
// clients may use to construct a DNS over HTTPS URI.
//
// See RFC 9461 (https://datatracker.ietf.org/doc/html/rfc9461)
// and RFC 9462 (https://datatracker.ietf.org/doc/html/rfc9462).
//
// A basic example of using the dohpath option together with the alpn
// option to indicate support for DNS over HTTPS on a certain path:
//
//	s := new(dns.SVCB)
//	s.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeSVCB, Class: dns.ClassINET}
//	e := new(dns.ALPN)
//	e.Alpn = []string{"h2", "h3"}
//	p := new(dns.DOHPATH)
//	p.Template = "/dns-query{?dns}"
//	s.Value = append(s.Value, e, p)
//
// The parsing currently doesn't validate that Template is a valid
// RFC 6570 URI template.
type DOHPATH struct {
	Template string
}

func (s *DOHPATH) String() string        { return svcbParamToStr([]byte(s.Template)) }
func (s *DOHPATH) Len() int              { return len(s.Template) }
func (s *DOHPATH) pack() ([]byte, error) { return []byte(s.Template), nil }

func (s *DOHPATH) unpack(b []byte) error {
	s.Template = string(b)
	return nil
}

func (s *DOHPATH) parse(b string) error {
	template, err := svcbParseParam(b)
	if err != nil {
		return fmt.Errorf("dns: svcbdohpath: %w", err)
	}
	s.Template = string(template)
	return nil
}

// The "ohttp" SvcParamKey is used to indicate that a service described in a SVCB RR
// can be accessed as a target using an associated gateway.
// Both the presentation and wire-format values for the "ohttp" parameter MUST be empty.
//
// See RFC 9460 (https://datatracker.ietf.org/doc/html/rfc9460/)
// and RFC 9230 (https://datatracker.ietf.org/doc/html/rfc9230/)
//
// A basic example of using the dohpath option together with the alpn
// option to indicate support for DNS over HTTPS on a certain path:
//
//	s := new(dns.SVCB)
//	s.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeSVCB, Class: dns.ClassINET}
//	e := new(dns.ALPN)
//	e.Alpn = []string{"h2", "h3"}
//	p := new(dns.OHTTP)
//	s.Value = append(s.Value, e, p)
type OHTTP struct{}

func (*OHTTP) pack() ([]byte, error) { return []byte{}, nil }
func (*OHTTP) String() string        { return "" }
func (*OHTTP) Len() int              { return 0 }

func (*OHTTP) unpack(b []byte) error {
	if len(b) != 0 {
		return errors.New("dns: svcbotthp: svcbotthp must have no value")
	}
	return nil
}

func (*OHTTP) parse(b string) error {
	if b != "" {
		return errors.New("dns: svcbotthp: svcbotthp must have no value")
	}
	return nil
}

// LOCAL pair is intended for experimental/private use. The key is recommended
// to be in the range [SVCB_PRIVATE_LOWER, SVCB_PRIVATE_UPPER].
// Basic use pattern for creating a keyNNNNN option:
//
//	h := new(dns.HTTPS)
//	h.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET}
//	e := new(dns.LOCAL)
//	e.KeyCode = 65400
//	e.Data = []byte("abc")
//	h.Value = append(h.Value, e)
type LOCAL struct {
	Data []byte // All byte sequences are allowed.
}

func (s *LOCAL) String() string { return svcbParamToStr(s.Data) }

// func (s *LOCAL) pack() ([]byte, error) { return slices.Clone(s.Data), nil }
func (s *LOCAL) Len() int { return len(s.Data) }

func (s *LOCAL) unpack(b []byte) error {
	s.Data = slices.Clone(b)
	return nil
}

func (s *LOCAL) parse(b string) error {
	data, err := svcbParseParam(b)
	if err != nil {
		return fmt.Errorf("dns: svcblocal: svcb private/experimental key %w", err)
	}
	s.Data = data
	return nil
}

// svcbParamStr converts the value of an SVCB parameter into a DNS presentation-format string.
func svcbParamToStr(s []byte) string {
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

// svcbParseParam parses a DNS presentation-format string into an SVCB parameter value.
func svcbParseParam(b string) ([]byte, error) {
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

func reverse(m map[Key]string) map[string]Key {
	n := make(map[string]Key, len(m))
	for u, s := range m {
		n[s] = u
	}
	return n
}
