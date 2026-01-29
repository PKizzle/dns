package dns

import (
	"encoding/base64"
	"net/netip"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns/deleg"
	"codeberg.org/miekg/dns/internal/ddd"
	"codeberg.org/miekg/dns/internal/dnslex"
	"codeberg.org/miekg/dns/svcb"
)

func (rr *A) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	value, err := netip.ParseAddr(l.Token)
	if l.Err || err != nil || !value.Is4() {
		return &ParseError{err: "bad A A", lex: l}
	}
	rr.Addr = value
	return toParseError(dnslex.Remainder(c))
}

func (rr *AAAA) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	value, err := netip.ParseAddr(l.Token)
	if l.Err || err != nil || !value.Is6() {
		return &ParseError{err: "bad AAAA AAAA", lex: l}
	}
	rr.Addr = value
	return toParseError(dnslex.Remainder(c))
}

func (rr *NS) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	name := dnsutilAbsolute(l.Token, o)
	if l.Err || name == "" {
		return &ParseError{err: "bad NS Ns", lex: l}
	}
	rr.Ns = name
	return toParseError(dnslex.Remainder(c))
}

func (rr *PTR) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	name := dnsutilAbsolute(l.Token, o)
	if l.Err || name == "" {
		return &ParseError{err: "bad PTR Ptr", lex: l}
	}
	rr.Ptr = name
	return toParseError(dnslex.Remainder(c))
}

func (rr *NSAPPTR) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	name := dnsutilAbsolute(l.Token, o)
	if l.Err || name == "" {
		return &ParseError{err: "bad NSAP-PTR Ptr", lex: l}
	}
	rr.Ptr = name
	return toParseError(dnslex.Remainder(c))
}

func (rr *RP) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	mbox := dnsutilAbsolute(l.Token, o)
	if l.Err || mbox == "" {
		return &ParseError{err: "bad RP Mbox", lex: l}
	}
	rr.Mbox = mbox

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rr.Txt = l.Token

	txt := dnsutilAbsolute(l.Token, o)
	if l.Err || txt == "" {
		return &ParseError{err: "bad RP Txt", lex: l}
	}
	rr.Txt = txt

	return toParseError(dnslex.Remainder(c))
}

func (rr *MR) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	name := dnsutilAbsolute(l.Token, o)
	if l.Err || name == "" {
		return &ParseError{err: "bad MR Mr", lex: l}
	}
	rr.Mr = name
	return toParseError(dnslex.Remainder(c))
}

func (rr *MB) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	name := dnsutilAbsolute(l.Token, o)
	if l.Err || name == "" {
		return &ParseError{err: "bad MB Mb", lex: l}
	}
	rr.Mb = name
	return toParseError(dnslex.Remainder(c))
}

func (rr *MG) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	name := dnsutilAbsolute(l.Token, o)
	if l.Err || name == "" {
		return &ParseError{err: "bad MG Mg", lex: l}
	}
	rr.Mg = name
	return toParseError(dnslex.Remainder(c))
}

func (rr *HINFO) parse(c *dnslex.Lexer, o string) *ParseError {
	chunks, e := endingToTxtSlice(c, "bad HINFO Fields")
	if e != nil {
		return e
	}

	if ln := len(chunks); ln == 0 {
		return nil
	} else if ln == 1 {
		// Can we split it?
		if out := strings.Fields(chunks[0]); len(out) > 1 {
			chunks = out
		} else {
			chunks = append(chunks, "")
		}
	}

	rr.Cpu = chunks[0]
	rr.Os = strings.Join(chunks[1:], " ")
	return nil
}

// according to RFC 1183 the parsing is identical to HINFO, so just use that code.
func (rr *ISDN) parse(c *dnslex.Lexer, o string) *ParseError {
	chunks, e := endingToTxtSlice(c, "bad ISDN Fields")
	if e != nil {
		return e
	}

	if ln := len(chunks); ln == 0 {
		return nil
	} else if ln == 1 {
		// Can we split it?
		if out := strings.Fields(chunks[0]); len(out) > 1 {
			chunks = out
		} else {
			chunks = append(chunks, "")
		}
	}

	rr.Address = chunks[0]
	rr.SubAddress = strings.Join(chunks[1:], " ")

	return nil
}

func (rr *MINFO) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	rmail := dnsutilAbsolute(l.Token, o)
	if l.Err || rmail == "" {
		return &ParseError{err: "bad MINFO Rmail", lex: l}
	}
	rr.Rmail = rmail

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rr.Email = l.Token

	email := dnsutilAbsolute(l.Token, o)
	if l.Err || email == "" {
		return &ParseError{err: "bad MINFO Email", lex: l}
	}
	rr.Email = email

	return toParseError(dnslex.Remainder(c))
}

func (rr *MF) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	name := dnsutilAbsolute(l.Token, o)
	if l.Err || name == "" {
		return &ParseError{err: "bad MF Mf", lex: l}
	}
	rr.Mf = name
	return toParseError(dnslex.Remainder(c))
}

func (rr *MD) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	name := dnsutilAbsolute(l.Token, o)
	if l.Err || name == "" {
		return &ParseError{err: "bad MD Md", lex: l}
	}
	rr.Md = name
	return toParseError(dnslex.Remainder(c))
}

func (rr *MX) parse(c *dnslex.Lexer, o string) *ParseError { return parseMX(&rr.MX, c, o) }

func (rr *RT) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 16)
	if e != nil {
		return &ParseError{err: "bad RT Preference", lex: l}
	}
	rr.Preference = uint16(i)

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rr.Host = l.Token

	name := dnsutilAbsolute(l.Token, o)
	if l.Err || name == "" {
		return &ParseError{err: "bad RT Host", lex: l}
	}
	rr.Host = name

	return toParseError(dnslex.Remainder(c))
}

func (rr *AFSDB) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 16)
	if e != nil || l.Err {
		return &ParseError{err: "bad AFSDB Subtype", lex: l}
	}
	rr.Subtype = uint16(i)

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rr.Hostname = l.Token

	name := dnsutilAbsolute(l.Token, o)
	if l.Err || name == "" {
		return &ParseError{err: "bad AFSDB Hostname", lex: l}
	}
	rr.Hostname = name
	return toParseError(dnslex.Remainder(c))
}

func (rr *X25) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	if l.Err {
		return &ParseError{err: "bad X25 PSDNAddress", lex: l}
	}
	rr.PSDNAddress = l.Token
	return toParseError(dnslex.Remainder(c))
}

func (rr *KX) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 16)
	if e != nil || l.Err {
		return &ParseError{err: "bad KX Pref", lex: l}
	}
	rr.Preference = uint16(i)

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rr.Exchanger = l.Token

	name := dnsutilAbsolute(l.Token, o)
	if l.Err || name == "" {
		return &ParseError{err: "bad KX Exchanger", lex: l}
	}
	rr.Exchanger = name
	return toParseError(dnslex.Remainder(c))
}

func (rr *CNAME) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	name := dnsutilAbsolute(l.Token, o)
	if l.Err || name == "" {
		return &ParseError{err: "bad CNAME Target", lex: l}
	}
	rr.Target = name
	return toParseError(dnslex.Remainder(c))
}

func (rr *DNAME) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	name := dnsutilAbsolute(l.Token, o)
	if l.Err || name == "" {
		return &ParseError{err: "bad DNAME Target", lex: l}
	}
	rr.Target = name
	return toParseError(dnslex.Remainder(c))
}

func (rr *SOA) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	ns := dnsutilAbsolute(l.Token, o)
	if l.Err || ns == "" {
		return &ParseError{err: "bad SOA Ns", lex: l}
	}
	rr.Ns = ns

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rr.Mbox = l.Token

	mbox := dnsutilAbsolute(l.Token, o)
	if l.Err || mbox == "" {
		return &ParseError{err: "bad SOA Mbox", lex: l}
	}
	rr.Mbox = mbox

	c.Next() // dnslex.Blank

	var (
		v  uint32
		ok bool
	)
	for i := range 5 {
		l, _ = c.Next()
		if l.Err {
			return &ParseError{err: "bad SOA field", lex: l}
		}
		if j, err := strconv.ParseUint(l.Token, 10, 32); err != nil {
			if i == 0 {
				// Serial must be a number
				return &ParseError{err: "bad SOA Serial", lex: l}
			}
			// We allow other fields to be unitful duration strings
			if v, ok = stringToTTL(l.Token); !ok {
				return &ParseError{err: "bad SOA field", lex: l}
			}
		} else {
			v = uint32(j)
		}
		switch i {
		case 0:
			rr.Serial = v
			c.Next() // dnslex.Blank
		case 1:
			rr.Refresh = v
			c.Next() // dnslex.Blank
		case 2:
			rr.Retry = v
			c.Next() // dnslex.Blank
		case 3:
			rr.Expire = v
			c.Next() // dnslex.Blank
		case 4:
			rr.Minttl = v
		}
	}
	return toParseError(dnslex.Remainder(c))
}

func (rr *SRV) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 16)
	if e != nil || l.Err {
		return &ParseError{err: "bad SRV Priority", lex: l}
	}
	rr.Priority = uint16(i)

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	i, e1 := strconv.ParseUint(l.Token, 10, 16)
	if e1 != nil || l.Err {
		return &ParseError{err: "bad SRV Weight", lex: l}
	}
	rr.Weight = uint16(i)

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	i, e2 := strconv.ParseUint(l.Token, 10, 16)
	if e2 != nil || l.Err {
		return &ParseError{err: "bad SRV Port", lex: l}
	}
	rr.Port = uint16(i)

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rr.Target = l.Token

	name := dnsutilAbsolute(l.Token, o)
	if l.Err || name == "" {
		return &ParseError{err: "bad SRV Target", lex: l}
	}
	rr.Target = name
	return toParseError(dnslex.Remainder(c))
}

func (rr *NAPTR) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 16)
	if e != nil || l.Err {
		return &ParseError{err: "bad NAPTR Order", lex: l}
	}
	rr.Order = uint16(i)

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	i, e1 := strconv.ParseUint(l.Token, 10, 16)
	if e1 != nil || l.Err {
		return &ParseError{err: "bad NAPTR Preference", lex: l}
	}
	rr.Preference = uint16(i)

	// Flags
	c.Next()        // dnslex.Blank
	l, _ = c.Next() // _QUOTE
	if l.Value != dnslex.Quote {
		return &ParseError{err: "bad NAPTR Flags", lex: l}
	}
	l, _ = c.Next() // Either String or Quote
	switch l.Value {
	case dnslex.String:
		rr.Flags = l.Token
		l, _ = c.Next() // _QUOTE
		if l.Value != dnslex.Quote {
			return &ParseError{err: "bad NAPTR Flags", lex: l}
		}
	case dnslex.Quote:
		rr.Flags = ""
	default:
		return &ParseError{err: "bad NAPTR Flags", lex: l}
	}

	// Service
	c.Next()        // dnslex.Blank
	l, _ = c.Next() // _QUOTE
	if l.Value != dnslex.Quote {
		return &ParseError{err: "bad NAPTR Service", lex: l}
	}
	l, _ = c.Next() // Either String or Quote
	switch l.Value {
	case dnslex.String:
		rr.Service = l.Token
		l, _ = c.Next() // _QUOTE
		if l.Value != dnslex.Quote {
			return &ParseError{err: "bad NAPTR Service", lex: l}
		}
	case dnslex.Quote:
		rr.Service = ""
	default:
		return &ParseError{err: "bad NAPTR Service", lex: l}
	}

	// Regexp
	c.Next()        // dnslex.Blank
	l, _ = c.Next() // _QUOTE
	if l.Value != dnslex.Quote {
		return &ParseError{err: "bad NAPTR Regexp", lex: l}
	}
	l, _ = c.Next() // Either String or Quote
	switch l.Value {
	case dnslex.String:
		rr.Regexp = l.Token
		l, _ = c.Next() // _QUOTE
		if l.Value != dnslex.Quote {
			return &ParseError{err: "bad NAPTR Regexp", lex: l}
		}
	case dnslex.Quote:
		rr.Regexp = ""
	default:
		return &ParseError{err: "bad NAPTR Regexp", lex: l}
	}

	// After quote no space??
	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rr.Replacement = l.Token

	name := dnsutilAbsolute(l.Token, o)
	if l.Err || name == "" {
		return &ParseError{err: "bad NAPTR Replacement", lex: l}
	}
	rr.Replacement = name
	return toParseError(dnslex.Remainder(c))
}

func (rr *TALINK) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	previousName := dnsutilAbsolute(l.Token, o)
	if l.Err || previousName == "" {
		return &ParseError{err: "bad TALINK PreviousName", lex: l}
	}
	rr.PreviousName = previousName

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rr.NextName = l.Token

	nextName := dnsutilAbsolute(l.Token, o)
	if l.Err || nextName == "" {
		return &ParseError{err: "bad TALINK NextName", lex: l}
	}
	rr.NextName = nextName

	return toParseError(dnslex.Remainder(c))
}

func (rr *LOC) parse(c *dnslex.Lexer, o string) *ParseError {
	// Non zero defaults for LOC record, see RFC 1876, Section 3.
	rr.Size = 0x12     // 1e2 cm (1m)
	rr.HorizPre = 0x16 // 1e6 cm (10000m)
	rr.VertPre = 0x13  // 1e3 cm (10m)
	ok := false

	// North
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 32)
	if e != nil || l.Err || i > 90 {
		return &ParseError{err: "bad LOC Latitude", lex: l}
	}
	rr.Latitude = 1000 * 60 * 60 * uint32(i)

	c.Next() // dnslex.Blank
	// Either number, 'N' or 'S'
	l, _ = c.Next()
	if rr.Latitude, ok = locCheckNorth(l.Token, rr.Latitude); ok {
		goto East
	}
	if i, err := strconv.ParseUint(l.Token, 10, 32); err != nil || l.Err || i > 59 {
		return &ParseError{err: "bad LOC Latitude minutes", lex: l}
	} else {
		rr.Latitude += 1000 * 60 * uint32(i)
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	if i, err := strconv.ParseFloat(l.Token, 64); err != nil || l.Err || i < 0 || i >= 60 {
		return &ParseError{err: "bad LOC Latitude seconds", lex: l}
	} else {
		rr.Latitude += uint32(1000 * i)
	}
	c.Next() // dnslex.Blank
	// Either number, 'N' or 'S'
	l, _ = c.Next()
	if rr.Latitude, ok = locCheckNorth(l.Token, rr.Latitude); ok {
		goto East
	}
	// If still alive, flag an error
	return &ParseError{err: "bad LOC Latitude North/South", lex: l}

East:
	// East
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	if i, err := strconv.ParseUint(l.Token, 10, 32); err != nil || l.Err || i > 180 {
		return &ParseError{err: "bad LOC Longitude", lex: l}
	} else {
		rr.Longitude = 1000 * 60 * 60 * uint32(i)
	}
	c.Next() // dnslex.Blank
	// Either number, 'E' or 'W'
	l, _ = c.Next()
	if rr.Longitude, ok = locCheckEast(l.Token, rr.Longitude); ok {
		goto Altitude
	}
	if i, err := strconv.ParseUint(l.Token, 10, 32); err != nil || l.Err || i > 59 {
		return &ParseError{err: "bad LOC Longitude minutes", lex: l}
	} else {
		rr.Longitude += 1000 * 60 * uint32(i)
	}
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	if i, err := strconv.ParseFloat(l.Token, 64); err != nil || l.Err || i < 0 || i >= 60 {
		return &ParseError{err: "bad LOC Longitude seconds", lex: l}
	} else {
		rr.Longitude += uint32(1000 * i)
	}
	c.Next() // dnslex.Blank
	// Either number, 'E' or 'W'
	l, _ = c.Next()
	if rr.Longitude, ok = locCheckEast(l.Token, rr.Longitude); ok {
		goto Altitude
	}
	// If still alive, flag an error
	return &ParseError{err: "bad LOC Longitude East/West", lex: l}

Altitude:
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	if l.Token == "" || l.Err {
		return &ParseError{err: "bad LOC Altitude", lex: l}
	}
	if l.Token[len(l.Token)-1] == 'M' || l.Token[len(l.Token)-1] == 'm' {
		l.Token = l.Token[0 : len(l.Token)-1]
	}
	if i, err := strconv.ParseFloat(l.Token, 64); err != nil {
		return &ParseError{err: "bad LOC Altitude", lex: l}
	} else {
		rr.Altitude = uint32(i*100.0 + 10000000.0 + 0.5)
	}

	// And now optionally the other values
	l, _ = c.Next()
	count := 0
	for l.Value != dnslex.Newline && l.Value != dnslex.EOF {
		switch l.Value {
		case dnslex.String:
			switch count {
			case 0: // Size
				exp, m, ok := stringToCm(l.Token)
				if !ok {
					return &ParseError{err: "bad LOC Size", lex: l}
				}
				rr.Size = exp&0x0f | m<<4&0xf0
			case 1: // Horidnslex.Pre
				exp, m, ok := stringToCm(l.Token)
				if !ok {
					return &ParseError{err: "bad LOC Horidnslex.Pre", lex: l}
				}
				rr.HorizPre = exp&0x0f | m<<4&0xf0
			case 2: // VertPre
				exp, m, ok := stringToCm(l.Token)
				if !ok {
					return &ParseError{err: "bad LOC VertPre", lex: l}
				}
				rr.VertPre = exp&0x0f | m<<4&0xf0
			}
			count++
		case dnslex.Blank:
			// Ok
		default:
			return &ParseError{err: "bad LOC Size, Horidnslex.Pre or VertPre", lex: l}
		}
		l, _ = c.Next()
	}
	return nil
}

func (rr *HIP) parse(c *dnslex.Lexer, o string) *ParseError {
	// HitLength is not represented
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 8)
	if e != nil || l.Err {
		return &ParseError{err: "bad HIP PublicKeyAlgorithm", lex: l}
	}
	rr.PublicKeyAlgorithm = uint8(i)

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	if l.Token == "" || l.Err {
		return &ParseError{err: "bad HIP Hit", lex: l}
	}
	rr.Hit = l.Token // This can not contain spaces, see RFC 5205 Section 6.
	rr.HitLength = uint8(len(rr.Hit)) / 2

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	if l.Token == "" || l.Err {
		return &ParseError{err: "bad HIP PublicKey", lex: l}
	}
	rr.PublicKey = l.Token // This cannot contain spaces
	decodedPK, decodedPKerr := base64.StdEncoding.DecodeString(rr.PublicKey)
	if decodedPKerr != nil {
		return &ParseError{err: "bad HIP PublicKey", lex: l}
	}
	rr.PublicKeyLength = uint16(len(decodedPK))

	// RendezvousServers (if any)
	l, _ = c.Next()
	var xs []string
	for l.Value != dnslex.Newline && l.Value != dnslex.EOF {
		switch l.Value {
		case dnslex.String:
			name := dnsutilAbsolute(l.Token, o)
			if l.Err || name == "" {
				return &ParseError{err: "bad HIP RendezvousServers", lex: l}
			}
			xs = append(xs, name)
		case dnslex.Blank:
			// Ok
		default:
			return &ParseError{err: "bad HIP RendezvousServers", lex: l}
		}
		l, _ = c.Next()
	}

	rr.RendezvousServers = xs
	return nil
}

func (rr *CERT) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	if v, ok := StringToCertType[l.Token]; ok {
		rr.Type = v
	} else if i, err := strconv.ParseUint(l.Token, 10, 16); err != nil {
		return &ParseError{err: "bad CERT Type", lex: l}
	} else {
		rr.Type = uint16(i)
	}
	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	i, e := strconv.ParseUint(l.Token, 10, 16)
	if e != nil || l.Err {
		return &ParseError{err: "bad CERT KeyTag", lex: l}
	}
	rr.KeyTag = uint16(i)
	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	if v, ok := StringToAlgorithm[l.Token]; ok {
		rr.Algorithm = v
	} else if i, err := strconv.ParseUint(l.Token, 10, 8); err != nil {
		return &ParseError{err: "bad CERT Algorithm", lex: l}
	} else {
		rr.Algorithm = uint8(i)
	}
	s, e1 := endingToString(c, "bad CERT Certificate")
	if e1 != nil {
		return e1
	}
	rr.Certificate = s
	return nil
}

func (rr *OPENPGPKEY) parse(c *dnslex.Lexer, o string) *ParseError {
	s, e := endingToString(c, "bad OPENPGPKEY PublicKey")
	if e != nil {
		return e
	}
	rr.PublicKey = s
	return nil
}

func (rr *CSYNC) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	j, e := strconv.ParseUint(l.Token, 10, 32)
	if e != nil {
		// Serial must be a number
		return &ParseError{err: "bad CSYNC serial", lex: l}
	}
	rr.Serial = uint32(j)

	c.Next() // dnslex.Blank

	l, _ = c.Next()
	j, e1 := strconv.ParseUint(l.Token, 10, 16)
	if e1 != nil {
		// Serial must be a number
		return &ParseError{err: "bad CSYNC flags", lex: l}
	}
	rr.Flags = uint16(j)

	rr.TypeBitMap = make([]uint16, 0)
	var (
		k  uint16
		ok bool
	)
	l, _ = c.Next()
	for l.Value != dnslex.Newline && l.Value != dnslex.EOF {
		switch l.Value {
		case dnslex.Blank:
			// Ok
		case dnslex.String:
			tokenUpper := strings.ToUpper(l.Token)
			if k, ok = StringToType[tokenUpper]; !ok {
				if k, ok = typeToInt(l.Token); !ok {
					return &ParseError{err: "bad CSYNC TypeBitMap", lex: l}
				}
			}
			rr.TypeBitMap = append(rr.TypeBitMap, k)
		default:
			return &ParseError{err: "bad CSYNC TypeBitMap", lex: l}
		}
		l, _ = c.Next()
	}
	return nil
}

func (rr *ZONEMD) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 32)
	if e != nil || l.Err {
		return &ParseError{err: "bad ZONEMD Serial", lex: l}
	}
	rr.Serial = uint32(i)

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	i, e1 := strconv.ParseUint(l.Token, 10, 8)
	if e1 != nil || l.Err {
		return &ParseError{err: "bad ZONEMD Scheme", lex: l}
	}
	rr.Scheme = uint8(i)

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	i, err := strconv.ParseUint(l.Token, 10, 8)
	if err != nil || l.Err {
		return &ParseError{err: "bad ZONEMD Hash Algorithm", lex: l}
	}
	rr.Hash = uint8(i)

	s, e2 := endingToString(c, "bad ZONEMD Digest")
	if e2 != nil {
		return e2
	}
	rr.Digest = s
	return nil
}

func (rr *SIG) parse(c *dnslex.Lexer, o string) *ParseError { return rr.RRSIG.parse(c, o) }

func (rr *RRSIG) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	tokenUpper := strings.ToUpper(l.Token)
	if t, ok := StringToType[tokenUpper]; !ok {
		if strings.HasPrefix(tokenUpper, "TYPE") {
			t, ok = typeToInt(l.Token)
			if !ok {
				return &ParseError{err: "bad RRSIG Typecovered", lex: l}
			}
			rr.TypeCovered = t
		} else {
			return &ParseError{err: "bad RRSIG Typecovered", lex: l}
		}
	} else {
		rr.TypeCovered = t
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	if l.Err {
		return &ParseError{err: "bad RRSIG Algorithm", lex: l}
	}
	i, e := strconv.ParseUint(l.Token, 10, 8)
	rr.Algorithm = uint8(i) // if 0 we'll check the mnemonic in the if
	if e != nil {
		v, ok := StringToAlgorithm[l.Token]
		if !ok {
			return &ParseError{err: "bad RRSIG Algorithm", lex: l}
		}
		rr.Algorithm = v
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	i, e1 := strconv.ParseUint(l.Token, 10, 8)
	if e1 != nil || l.Err {
		return &ParseError{err: "bad RRSIG Labels", lex: l}
	}
	rr.Labels = uint8(i)

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	i, e2 := strconv.ParseUint(l.Token, 10, 32)
	if e2 != nil || l.Err {
		return &ParseError{err: "bad RRSIG OrigTTL", lex: l}
	}
	rr.OrigTTL = uint32(i)

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	if i, err := dnsutilStringToTime(l.Token); err != nil {
		// Try to see if all numeric and use it as epoch
		if i, err := strconv.ParseUint(l.Token, 10, 32); err == nil {
			rr.Expiration = uint32(i)
		} else {
			return &ParseError{err: "bad RRSIG Expiration", lex: l}
		}
	} else {
		rr.Expiration = i
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	if i, err := dnsutilStringToTime(l.Token); err != nil {
		if i, err := strconv.ParseUint(l.Token, 10, 32); err == nil {
			rr.Inception = uint32(i)
		} else {
			return &ParseError{err: "bad RRSIG Inception", lex: l}
		}
	} else {
		rr.Inception = i
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	i, e3 := strconv.ParseUint(l.Token, 10, 16)
	if e3 != nil || l.Err {
		return &ParseError{err: "bad RRSIG KeyTag", lex: l}
	}
	rr.KeyTag = uint16(i)

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rr.SignerName = l.Token
	name := dnsutilAbsolute(l.Token, o)
	if l.Err || name == "" {
		return &ParseError{err: "bad RRSIG SignerName", lex: l}
	}
	rr.SignerName = name

	s, e4 := endingToString(c, "bad RRSIG Signature")
	if e4 != nil {
		return e4
	}
	rr.Signature = s

	return nil
}

func (rr *NXT) parse(c *dnslex.Lexer, o string) *ParseError { return rr.NSEC.parse(c, o) }

func (rr *NSEC) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	name := dnsutilAbsolute(l.Token, o)
	if l.Err || name == "" {
		return &ParseError{err: "bad NSEC NextDomain", lex: l}
	}
	rr.NextDomain = name

	rr.TypeBitMap = make([]uint16, 0)
	var (
		k  uint16
		ok bool
	)
	l, _ = c.Next()
	for l.Value != dnslex.Newline && l.Value != dnslex.EOF {
		switch l.Value {
		case dnslex.Blank:
			// Ok
		case dnslex.String:
			tokenUpper := strings.ToUpper(l.Token)
			if k, ok = StringToType[tokenUpper]; !ok {
				if k, ok = typeToInt(l.Token); !ok {
					return &ParseError{err: "bad NSEC TypeBitMap", lex: l}
				}
			}
			rr.TypeBitMap = append(rr.TypeBitMap, k)
		default:
			return &ParseError{err: "bad NSEC TypeBitMap", lex: l}
		}
		l, _ = c.Next()
	}
	return nil
}

func (rr *NSEC3) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 8)
	if e != nil || l.Err {
		return &ParseError{err: "bad NSEC3 Hash", lex: l}
	}
	rr.Hash = uint8(i)
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	i, e1 := strconv.ParseUint(l.Token, 10, 8)
	if e1 != nil || l.Err {
		return &ParseError{err: "bad NSEC3 Flags", lex: l}
	}
	rr.Flags = uint8(i)
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	i, e2 := strconv.ParseUint(l.Token, 10, 16)
	if e2 != nil || l.Err {
		return &ParseError{err: "bad NSEC3 Iterations", lex: l}
	}
	rr.Iterations = uint16(i)
	c.Next()
	l, _ = c.Next()
	if l.Token == "" || l.Err {
		return &ParseError{err: "bad NSEC3 Salt", lex: l}
	}
	if l.Token != "-" {
		rr.SaltLength = uint8(len(l.Token)) / 2
		rr.Salt = l.Token
	}

	c.Next()
	l, _ = c.Next()
	if l.Token == "" || l.Err {
		return &ParseError{err: "bad NSEC3 NextDomain", lex: l}
	}
	rr.HashLength = 20 // Fix for NSEC3 (sha1 160 bits)
	rr.NextDomain = l.Token

	rr.TypeBitMap = make([]uint16, 0)
	var (
		k  uint16
		ok bool
	)
	l, _ = c.Next()
	for l.Value != dnslex.Newline && l.Value != dnslex.EOF {
		switch l.Value {
		case dnslex.Blank:
			// Ok
		case dnslex.String:
			tokenUpper := strings.ToUpper(l.Token)
			if k, ok = StringToType[tokenUpper]; !ok {
				if k, ok = typeToInt(l.Token); !ok {
					return &ParseError{err: "bad NSEC3 TypeBitMap", lex: l}
				}
			}
			rr.TypeBitMap = append(rr.TypeBitMap, k)
		default:
			return &ParseError{err: "bad NSEC3 TypeBitMap", lex: l}
		}
		l, _ = c.Next()
	}
	return nil
}

func (rr *NSEC3PARAM) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 8)
	if e != nil || l.Err {
		return &ParseError{err: "bad NSEC3PARAM Hash", lex: l}
	}
	rr.Hash = uint8(i)
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	i, e1 := strconv.ParseUint(l.Token, 10, 8)
	if e1 != nil || l.Err {
		return &ParseError{err: "bad NSEC3PARAM Flags", lex: l}
	}
	rr.Flags = uint8(i)
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	i, e2 := strconv.ParseUint(l.Token, 10, 16)
	if e2 != nil || l.Err {
		return &ParseError{err: "bad NSEC3PARAM Iterations", lex: l}
	}
	rr.Iterations = uint16(i)
	c.Next()
	l, _ = c.Next()
	if l.Token != "-" {
		rr.SaltLength = uint8(len(l.Token) / 2)
		rr.Salt = l.Token
	}
	return toParseError(dnslex.Remainder(c))
}

func (rr *EUI48) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	if len(l.Token) != 17 || l.Err {
		return &ParseError{err: "bad EUI48 Address", lex: l}
	}
	addr := make([]byte, 12)
	dash := 0
	for i := 0; i < 10; i += 2 {
		addr[i] = l.Token[i+dash]
		addr[i+1] = l.Token[i+1+dash]
		dash++
		if l.Token[i+1+dash] != '-' {
			return &ParseError{err: "bad EUI48 Address", lex: l}
		}
	}
	addr[10] = l.Token[15]
	addr[11] = l.Token[16]

	i, e := strconv.ParseUint(string(addr), 16, 48)
	if e != nil {
		return &ParseError{err: "bad EUI48 Address", lex: l}
	}
	rr.Address = i
	return toParseError(dnslex.Remainder(c))
}

func (rr *EUI64) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	if len(l.Token) != 23 || l.Err {
		return &ParseError{err: "bad EUI64 Address", lex: l}
	}
	addr := make([]byte, 16)
	dash := 0
	for i := 0; i < 14; i += 2 {
		addr[i] = l.Token[i+dash]
		addr[i+1] = l.Token[i+1+dash]
		dash++
		if l.Token[i+1+dash] != '-' {
			return &ParseError{err: "bad EUI64 Address", lex: l}
		}
	}
	addr[14] = l.Token[21]
	addr[15] = l.Token[22]

	i, e := strconv.ParseUint(string(addr), 16, 64)
	if e != nil {
		return &ParseError{err: "bad EUI68 Address", lex: l}
	}
	rr.Address = i
	return toParseError(dnslex.Remainder(c))
}

func (rr *SSHFP) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 8)
	if e != nil || l.Err {
		return &ParseError{err: "bad SSHFP Algorithm", lex: l}
	}
	rr.Algorithm = uint8(i)
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	i, e1 := strconv.ParseUint(l.Token, 10, 8)
	if e1 != nil || l.Err {
		return &ParseError{err: "bad SSHFP Type", lex: l}
	}
	rr.Type = uint8(i)
	c.Next() // dnslex.Blank
	s, e2 := endingToString(c, "bad SSHFP Fingerprint")
	if e2 != nil {
		return e2
	}
	rr.FingerPrint = s
	return nil
}

func (rr *DNSKEY) parseDNSKEY(c *dnslex.Lexer, o, typ string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 16)
	if e != nil || l.Err {
		return &ParseError{err: "bad " + typ + " Flags", lex: l}
	}
	rr.Flags = uint16(i)
	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	i, e1 := strconv.ParseUint(l.Token, 10, 8)
	if e1 != nil || l.Err {
		return &ParseError{err: "bad " + typ + " Protocol", lex: l}
	}
	rr.Protocol = uint8(i)
	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	i, e2 := strconv.ParseUint(l.Token, 10, 8)
	if e2 != nil || l.Err {
		return &ParseError{err: "bad " + typ + " Algorithm", lex: l}
	}
	rr.Algorithm = uint8(i)
	s, e3 := endingToString(c, "bad "+typ+" PublicKey")
	if e3 != nil {
		return e3
	}
	rr.PublicKey = s
	return nil
}

func (rr *DNSKEY) parse(c *dnslex.Lexer, o string) *ParseError {
	return parseDNSKEY(&rr.DNSKEY, o, "DNSKEY")
}
func (rr *KEY) parse(c *dnslex.Lexer, o string) *ParseError {
	return parseDNSKEY(&rr.DNSKEY.DNSKEY, c, o, "KEY")
}
func (rr *CDNSKEY) parse(c *dnslex.Lexer, o string) *ParseError {
	return parseDNSKEY(&rr.DNSKEY.DNSKEY, c, o, "KEY")
}
func (rr *DS) parse(c *dnslex.Lexer, o string) *ParseError  { return parseDS(&rr.DS, c, o, "DS") }
func (rr *DLV) parse(c *dnslex.Lexer, o string) *ParseError { return parseDS(&rr.DS.DS, c, o, "DLV") }
func (rr *CDS) parse(c *dnslex.Lexer, o string) *ParseError { return parseDS(&rr.DS.DS, c, o, "CDS") }

func (rr *RKEY) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 16)
	if e != nil || l.Err {
		return &ParseError{err: "bad RKEY Flags", lex: l}
	}
	rr.Flags = uint16(i)
	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	i, e1 := strconv.ParseUint(l.Token, 10, 8)
	if e1 != nil || l.Err {
		return &ParseError{err: "bad RKEY Protocol", lex: l}
	}
	rr.Protocol = uint8(i)
	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	i, e2 := strconv.ParseUint(l.Token, 10, 8)
	if e2 != nil || l.Err {
		return &ParseError{err: "bad RKEY Algorithm", lex: l}
	}
	rr.Algorithm = uint8(i)
	s, e3 := endingToString(c, "bad RKEY PublicKey")
	if e3 != nil {
		return e3
	}
	rr.PublicKey = s
	return nil
}

func (rr *EID) parse(c *dnslex.Lexer, o string) *ParseError {
	s, e := endingToString(c, "bad EID Endpoint")
	if e != nil {
		return e
	}
	rr.Endpoint = s
	return nil
}

func (rr *NIMLOC) parse(c *dnslex.Lexer, o string) *ParseError {
	s, e := endingToString(c, "bad NIMLOC Locator")
	if e != nil {
		return e
	}
	rr.Locator = s
	return nil
}

func (rr *GPOS) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	_, e := strconv.ParseFloat(l.Token, 64)
	if e != nil || l.Err {
		return &ParseError{err: "bad GPOS Longitude", lex: l}
	}
	rr.Longitude = l.Token
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	_, e1 := strconv.ParseFloat(l.Token, 64)
	if e1 != nil || l.Err {
		return &ParseError{err: "bad GPOS Latitude", lex: l}
	}
	rr.Latitude = l.Token
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	_, e2 := strconv.ParseFloat(l.Token, 64)
	if e2 != nil || l.Err {
		return &ParseError{err: "bad GPOS Altitude", lex: l}
	}
	rr.Altitude = l.Token
	return toParseError(dnslex.Remainder(c))
}

func (rr *DS) parseDS(c *dnslex.Lexer, o, typ string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 16)
	if e != nil || l.Err {
		return &ParseError{err: "bad " + typ + " KeyTag", lex: l}
	}
	rr.KeyTag = uint16(i)
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	if i, err := strconv.ParseUint(l.Token, 10, 8); err != nil {
		tokenUpper := strings.ToUpper(l.Token)
		i, ok := StringToAlgorithm[tokenUpper]
		if !ok || l.Err {
			return &ParseError{err: "bad " + typ + " Algorithm", lex: l}
		}
		rr.Algorithm = i
	} else {
		rr.Algorithm = uint8(i)
	}
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	i, e1 := strconv.ParseUint(l.Token, 10, 8)
	if e1 != nil || l.Err {
		return &ParseError{err: "bad " + typ + " DigestType", lex: l}
	}
	rr.DigestType = uint8(i)
	s, e2 := endingToString(c, "bad "+typ+" Digest")
	if e2 != nil {
		return e2
	}
	rr.Digest = s
	return nil
}

func (rr *TA) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 16)
	if e != nil || l.Err {
		return &ParseError{err: "bad TA KeyTag", lex: l}
	}
	rr.KeyTag = uint16(i)
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	if i, err := strconv.ParseUint(l.Token, 10, 8); err != nil {
		tokenUpper := strings.ToUpper(l.Token)
		i, ok := StringToAlgorithm[tokenUpper]
		if !ok || l.Err {
			return &ParseError{err: "bad TA Algorithm", lex: l}
		}
		rr.Algorithm = i
	} else {
		rr.Algorithm = uint8(i)
	}
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	i, e1 := strconv.ParseUint(l.Token, 10, 8)
	if e1 != nil || l.Err {
		return &ParseError{err: "bad TA DigestType", lex: l}
	}
	rr.DigestType = uint8(i)
	s, e2 := endingToString(c, "bad TA Digest")
	if e2 != nil {
		return e2
	}
	rr.Digest = s
	return nil
}

func (rr *TLSA) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 8)
	if e != nil || l.Err {
		return &ParseError{err: "bad TLSA Usage", lex: l}
	}
	rr.Usage = uint8(i)
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	i, e1 := strconv.ParseUint(l.Token, 10, 8)
	if e1 != nil || l.Err {
		return &ParseError{err: "bad TLSA Selector", lex: l}
	}
	rr.Selector = uint8(i)
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	i, e2 := strconv.ParseUint(l.Token, 10, 8)
	if e2 != nil || l.Err {
		return &ParseError{err: "bad TLSA MatchingType", lex: l}
	}
	rr.MatchingType = uint8(i)
	// So this needs be e2 (i.e. different than e), because...??t
	s, e3 := endingToString(c, "bad TLSA Certificate")
	if e3 != nil {
		return e3
	}
	rr.Certificate = s
	return nil
}

func (rr *SMIMEA) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 8)
	if e != nil || l.Err {
		return &ParseError{err: "bad SMIMEA Usage", lex: l}
	}
	rr.Usage = uint8(i)
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	i, e1 := strconv.ParseUint(l.Token, 10, 8)
	if e1 != nil || l.Err {
		return &ParseError{err: "bad SMIMEA Selector", lex: l}
	}
	rr.Selector = uint8(i)
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	i, e2 := strconv.ParseUint(l.Token, 10, 8)
	if e2 != nil || l.Err {
		return &ParseError{err: "bad SMIMEA MatchingType", lex: l}
	}
	rr.MatchingType = uint8(i)
	// So this needs be e2 (i.e. different than e), because...??t
	s, e3 := endingToString(c, "bad SMIMEA Certificate")
	if e3 != nil {
		return e3
	}
	rr.Certificate = s
	return nil
}

func (rr *RFC3597) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	if l.Token != "\\#" {
		return &ParseError{err: "bad RFC3597 Rdata", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rdlength, e := strconv.ParseUint(l.Token, 10, 16)
	if e != nil || l.Err {
		return &ParseError{err: "bad RFC3597 Rdata ", lex: l}
	}

	s, e1 := endingToString(c, "bad RFC3597 Rdata")
	if e1 != nil {
		return e1
	}
	if int(rdlength)*2 != len(s) {
		return &ParseError{err: "bad RFC3597 Rdata", lex: l}
	}
	rr.RFC3597.Data = s
	return nil
}

func (rr *SPF) parse(c *dnslex.Lexer, o string) *ParseError {
	s, e := endingToTxtSlice(c, "bad SPF Txt")
	if e != nil {
		return e
	}
	rr.Txt = s
	return nil
}

func (rr *AVC) parse(c *dnslex.Lexer, o string) *ParseError {
	s, e := endingToTxtSlice(c, "bad AVC Txt")
	if e != nil {
		return e
	}
	rr.Txt = s
	return nil
}

func (rr *TXT) parse(c *dnslex.Lexer, o string) *ParseError {
	// no dnslex.Blank reading here, because all this rdata is TXT
	s, e := endingToTxtSlice(c, "bad TXT Txt")
	if e != nil {
		return e
	}
	rr.Txt = s
	return nil
}

// identical to setTXT
func (rr *NINFO) parse(c *dnslex.Lexer, o string) *ParseError {
	s, e := endingToTxtSlice(c, "bad NINFO ZSData")
	if e != nil {
		return e
	}
	rr.ZSData = s
	return nil
}

// Uses the same format as TXT
func (rr *RESINFO) parse(c *dnslex.Lexer, o string) *ParseError {
	s, e := endingToTxtSlice(c, "bad RESINFO Resinfo")
	if e != nil {
		return e
	}
	rr.Txt = s
	return nil
}

func (rr *WALLET) parse(c *dnslex.Lexer, o string) *ParseError {
	s, e := endingToTxtSlice(c, "bad WALLET Txt")
	if e != nil {
		return e
	}
	rr.Txt = s
	return nil
}

func (rr *CLA) parse(c *dnslex.Lexer, o string) *ParseError {
	s, e := endingToTxtSlice(c, "bad CLA Txt")
	if e != nil {
		return e
	}
	rr.Txt = s
	return nil
}

func (rr *IPN) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 64)
	if e != nil || l.Err {
		return &ParseError{err: "bad IPN Node", lex: l}
	}
	rr.Node = uint64(i)
	return toParseError(dnslex.Remainder(c))
}

func (rr *URI) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 16)
	if e != nil || l.Err {
		return &ParseError{err: "bad URI Priority", lex: l}
	}
	rr.Priority = uint16(i)
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	i, e1 := strconv.ParseUint(l.Token, 10, 16)
	if e1 != nil || l.Err {
		return &ParseError{err: "bad URI Weight", lex: l}
	}
	rr.Weight = uint16(i)

	c.Next() // dnslex.Blank
	s, e2 := endingToTxtSlice(c, "bad URI Target")
	if e2 != nil {
		return e2
	}
	if len(s) != 1 {
		return &ParseError{err: "bad URI Target", lex: l}
	}
	rr.Target = s[0]
	return nil
}

func (rr *DHCID) parse(c *dnslex.Lexer, o string) *ParseError {
	// awesome record to parse!
	s, e := endingToString(c, "bad DHCID Digest")
	if e != nil {
		return e
	}
	rr.Digest = s
	return nil
}

func (rr *NID) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 16)
	if e != nil || l.Err {
		return &ParseError{err: "bad NID Preference", lex: l}
	}
	rr.Preference = uint16(i)
	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	u, e1 := stringToNodeID(l)
	if e1 != nil || l.Err {
		return e1
	}
	rr.NodeID = u
	return toParseError(dnslex.Remainder(c))
}

func (rr *L32) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 16)
	if e != nil || l.Err {
		return &ParseError{err: "bad L32 Preference", lex: l}
	}
	rr.Preference = uint16(i)
	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	loc, err := netip.ParseAddr(l.Token)
	if l.Err || err != nil || !loc.Is4() {
		return &ParseError{err: "bad L32 Locator", lex: l}
	}
	rr.Locator32 = loc
	return toParseError(dnslex.Remainder(c))
}

func (rr *LP) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 16)
	if e != nil || l.Err {
		return &ParseError{err: "bad LP Preference", lex: l}
	}
	rr.Preference = uint16(i)

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rr.Fqdn = l.Token
	name := dnsutilAbsolute(l.Token, o)
	if l.Err || name == "" {
		return &ParseError{err: "bad LP Fqdn", lex: l}
	}
	rr.Fqdn = name
	return toParseError(dnslex.Remainder(c))
}

func (rr *L64) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 16)
	if e != nil || l.Err {
		return &ParseError{err: "bad L64 Preference", lex: l}
	}
	rr.Preference = uint16(i)
	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	u, e1 := stringToNodeID(l)
	if e1 != nil || l.Err {
		return e1
	}
	rr.Locator64 = u
	return toParseError(dnslex.Remainder(c))
}

func (rr *UID) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 32)
	if e != nil || l.Err {
		return &ParseError{err: "bad UID Uid", lex: l}
	}
	rr.Uid = uint32(i)
	return toParseError(dnslex.Remainder(c))
}

func (rr *GID) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 32)
	if e != nil || l.Err {
		return &ParseError{err: "bad GID Gid", lex: l}
	}
	rr.Gid = uint32(i)
	return toParseError(dnslex.Remainder(c))
}

func (rr *UINFO) parse(c *dnslex.Lexer, o string) *ParseError {
	s, e := endingToTxtSlice(c, "bad UINFO Uinfo")
	if e != nil {
		return e
	}
	if ln := len(s); ln == 0 {
		return nil
	}
	rr.Uinfo = s[0] // silently discard anything after the first character-string
	return nil
}

func (rr *PX) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 16)
	if e != nil || l.Err {
		return &ParseError{err: "bad PX Preference", lex: l}
	}
	rr.Preference = uint16(i)

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rr.Map822 = l.Token
	map822 := dnsutilAbsolute(l.Token, o)
	if l.Err || map822 == "" {
		return &ParseError{err: "bad PX Map822", lex: l}
	}
	rr.Map822 = map822

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rr.Mapx400 = l.Token
	mapx400 := dnsutilAbsolute(l.Token, o)
	if l.Err || mapx400 == "" {
		return &ParseError{err: "bad PX Mapx400", lex: l}
	}
	rr.Mapx400 = mapx400
	return toParseError(dnslex.Remainder(c))
}

func (rr *CAA) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 8)
	if e != nil || l.Err {
		return &ParseError{err: "bad CAA Flag", lex: l}
	}
	rr.Flag = uint8(i)

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	if l.Value != dnslex.String {
		return &ParseError{err: "bad CAA Tag", lex: l}
	}
	rr.Tag = l.Token

	c.Next() // dnslex.Blank
	s, e1 := endingToTxtSlice(c, "bad CAA Value")
	if e1 != nil {
		return e1
	}
	if len(s) != 1 {
		return &ParseError{err: "bad CAA Value", lex: l}
	}
	rr.Value = s[0]
	return nil
}

func (rr *TKEY) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()

	// Algorithm
	if l.Value != dnslex.String {
		return &ParseError{err: "bad TKEY Algorithm", lex: l}
	}
	rr.Algorithm = l.Token
	c.Next() // dnslex.Blank

	// Get the key length and key values
	l, _ = c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 8)
	if e != nil || l.Err {
		return &ParseError{err: "bad TKEY KeySize", lex: l}
	}
	rr.KeySize = uint16(i)
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	if l.Value != dnslex.String {
		return &ParseError{err: "bad TKEY Key", lex: l}
	}
	rr.Key = l.Token
	c.Next() // dnslex.Blank

	// Get the otherdata length and string data
	l, _ = c.Next()
	i, e1 := strconv.ParseUint(l.Token, 10, 8)
	if e1 != nil || l.Err {
		return &ParseError{err: "bad TKEY OtherLen", lex: l}
	}
	rr.OtherLen = uint16(i)
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	if l.Value != dnslex.String {
		return &ParseError{err: "bad TKEY OtherData", lex: l}
	}
	rr.OtherData = l.Token
	return nil
}

func (rr *SVCB) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 16)
	if e != nil || l.Err {
		return &ParseError{file: l.Token, err: "bad SVCB Priority", lex: l}
	}
	rr.Priority = uint16(i)

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rr.Target = l.Token

	name := dnsutilAbsolute(l.Token, o)
	if l.Err || name == "" {
		return &ParseError{file: l.Token, err: "bad SVCB Target", lex: l}
	}
	rr.Target = name

	// Values (if any)
	l, _ = c.Next()
	var xs []svcb.Pair
	// Helps require whitespace between pairs.
	// Prevents key1000="a"key1001=...
	canHaveNextKey := true
	for l.Value != dnslex.Newline && l.Value != dnslex.EOF {
		switch l.Value {
		case dnslex.String:
			if !canHaveNextKey {
				// The key we can now read was probably meant to be
				// a part of the last value.
				return &ParseError{file: l.Token, err: "bad SVCB value quotation", lex: l}
			}

			// In key=value pairs, value does not have to be quoted unless value
			// contains whitespace. And keys don't need to have values.
			// Similarly, keys with an equality signs after them don't need values.
			// l.Token includes at least up to the first equality sign.
			idx := strings.IndexByte(l.Token, '=')
			var key, value string
			if idx < 0 {
				// Key with no value and no equality sign
				key = l.Token
			} else if idx == 0 {
				return &ParseError{file: l.Token, err: "bad SVCB Key", lex: l}
			} else {
				key, value = l.Token[:idx], l.Token[idx+1:]

				if value == "" {
					// We have a key and an equality sign. Maybe we have nothing
					// after "=" or we have a double quote.
					l, _ = c.Next()
					if l.Value == dnslex.Quote {
						// Only needed when value ends with double quotes.
						// Any value starting with dnslex.Quote ends with it.
						canHaveNextKey = false

						l, _ = c.Next()
						switch l.Value {
						case dnslex.String:
							// We have a value in double quotes.
							value = l.Token
							l, _ = c.Next()
							if l.Value != dnslex.Quote {
								return &ParseError{file: l.Token, err: "SVCB unterminated value", lex: l}
							}
						case dnslex.Quote:
							// There's nothing in double quotes.
						default:
							return &ParseError{file: l.Token, err: "bad SVCB Pair", lex: l}
						}
					}
				}
			}
			pairFn := svcb.KeyToPair(svcb.StringToKey(key))
			if pairFn == nil {
				return &ParseError{file: l.Token, err: "bad SVCB Key", lex: l}
			}
			pair := pairFn()
			if err := svcb.Parse(pair, value, o); err != nil {
				return &ParseError{file: l.Token, wrappedErr: err, lex: l}
			}
			xs = append(xs, pair)
		case dnslex.Quote:
			return &ParseError{file: l.Token, err: "SVCB Key can't contain double quotes", lex: l}
		case dnslex.Blank:
			canHaveNextKey = true
		default:
			return &ParseError{file: l.Token, err: "bad SVCB Pairs", lex: l}
		}
		l, _ = c.Next()
	}

	// "In AliasMode, records SHOULD NOT include any SvcParams, and recipients MUST
	// ignore any SvcParams that are present."
	// However, we don't check rr.Priority == 0 && len(xs) > 0 here
	// It is the responsibility of the user of the library to check this.
	// This is to encourage the fixing of the source of this error.

	rr.Value = xs
	return nil
}

func (rr *HTTPS) parse(c *dnslex.Lexer, o string) *ParseError { return rr.SVCB.parse(c, o) }

func (rr *DELEG) parse(c *dnslex.Lexer, o string) *ParseError {
	// TODO(miek): unify with SVCB
	// Values (if any)
	l, _ := c.Next()
	var xs []deleg.Info
	// Helps require whitespace between infos.
	// Prevents key1000="a"key1001=...
	canHaveNextKey := true
	for l.Value != dnslex.Newline && l.Value != dnslex.EOF {
		switch l.Value {
		case dnslex.String:
			if !canHaveNextKey {
				// The key we can now read was probably meant to be
				// a part of the last value.
				return &ParseError{file: l.Token, err: "bad DELEG value quotation", lex: l}
			}

			// In key=value infos, value does not have to be quoted unless value
			// contains whitespace. And keys don't need to have values.
			// Similarly, keys with an equality signs after them don't need values.
			// l.Token includes at least up to the first equality sign.
			idx := strings.IndexByte(l.Token, '=')
			var key, value string
			if idx < 0 {
				// Key with no value and no equality sign
				key = l.Token
			} else if idx == 0 {
				return &ParseError{file: l.Token, err: "bad DELEG Key", lex: l}
			} else {
				key, value = l.Token[:idx], l.Token[idx+1:]

				if value == "" {
					// We have a key and an equality sign. Maybe we have nothing
					// after "=" or we have a double quote.
					l, _ = c.Next()
					if l.Value == dnslex.Quote {
						// Only needed when value ends with double quotes.
						// Any value starting with dnslex.Quote ends with it.
						canHaveNextKey = false

						l, _ = c.Next()
						switch l.Value {
						case dnslex.String:
							// We have a value in double quotes.
							value = l.Token
							l, _ = c.Next()
							if l.Value != dnslex.Quote {
								return &ParseError{file: l.Token, err: "DELEG unterminated value", lex: l}
							}
						case dnslex.Quote:
							// There's nothing in double quotes.
						default:
							return &ParseError{file: l.Token, err: "bad DELEG Info", lex: l}
						}
					}
				}
			}
			infoFn := deleg.KeyToInfo(deleg.StringToKey(key))
			if infoFn == nil {
				return &ParseError{file: l.Token, err: "bad DELEG Key", lex: l}
			}
			info := infoFn()
			if err := deleg.Parse(info, value, o); err != nil {
				return &ParseError{file: l.Token, wrappedErr: err, lex: l}
			}
			xs = append(xs, info)
		case dnslex.Quote:
			return &ParseError{file: l.Token, err: "DELEG Key can't contain double quotes", lex: l}
		case dnslex.Blank:
			canHaveNextKey = true
		default:
			return &ParseError{file: l.Token, err: "bad DELEG Infos", lex: l}
		}
		l, _ = c.Next()
	}
	rr.Value = xs
	return nil
}

func (rr *DELEGI) parse(c *dnslex.Lexer, o string) *ParseError { return rr.DELEG.parse(c, o) }

func (rr *DSYNC) parse(c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	rr.Type = StringToType[l.Token]

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	if strings.ToUpper(l.Token) == "NOTIFY" || l.Token == "1" {
		rr.Scheme = 1
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	port, err := strconv.ParseUint(l.Token, 10, 32)
	if err != nil {
		return &ParseError{err: "bad DSYNC Port"}
	}
	rr.Port = uint16(port)

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rr.Target = dnsutilAbsolute(l.Token, o)
	if l.Err || rr.Target == "" {
		return &ParseError{err: "bad DSYNC Target", lex: l}
	}
	return toParseError(dnslex.Remainder(c))
}

// escapedStringOffset finds the offset within a string (which may contain escape
// sequences) that corresponds to a certain byte offset. If the input offset is
// out of bounds, -1 is returned (which is *not* considered an error).
func escapedStringOffset(s string, desiredByteOffset int) (int, bool) {
	if desiredByteOffset == 0 {
		return 0, true
	}

	currentByteOffset, i := 0, 0

	for i < len(s) {
		currentByteOffset += 1

		// Skip escape sequences
		if s[i] != '\\' {
			// Single plain byte, not an escape sequence.
			i++
		} else if ddd.Is(s[i+1:]) {
			// Skip backslash and DDD.
			i += 4
		} else if len(s[i+1:]) < 1 {
			// No character following the backslash; that's an error.
			return 0, false
		} else {
			// Skip backslash and following byte.
			i += 2
		}

		if currentByteOffset >= desiredByteOffset {
			return i, true
		}
	}

	return -1, true
}

// Extract the rr number from TYPExxx
func typeToInt(token string) (uint16, bool) {
	offset := 4
	if len(token) < offset+1 {
		return 0, false
	}
	typ, err := strconv.ParseUint(token[offset:], 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(typ), true
}

// A remainder of the rdata with embedded spaces, return the parsed string (sans the spaces)
// or an error
func endingToString(c *dnslex.Lexer, errstr string) (string, *ParseError) {
	var s strings.Builder
	l, _ := c.Next() // dnslex.String
	for l.Value != dnslex.Newline && l.Value != dnslex.EOF {
		if l.Err {
			return s.String(), &ParseError{err: errstr, lex: l}
		}
		switch l.Value {
		case dnslex.String:
			s.WriteString(l.Token)
		case dnslex.Blank: // Ok
		default:
			return "", &ParseError{err: errstr, lex: l}
		}
		l, _ = c.Next()
	}

	return s.String(), nil
}

// A remainder of the rdata with embedded spaces, split on unquoted whitespace
// and return the parsed string slice or an error
func endingToTxtSlice(c *dnslex.Lexer, errstr string) ([]string, *ParseError) {
	// Get the remaining data until we see a dnslex.Newline
	l, _ := c.Next()
	if l.Err {
		return nil, &ParseError{err: errstr, lex: l}
	}

	// Build the slice
	s := make([]string, 0)
	quote := false
	empty := false
	for l.Value != dnslex.Newline && l.Value != dnslex.EOF {
		if l.Err {
			return nil, &ParseError{err: errstr, lex: l}
		}
		switch l.Value {
		case dnslex.String:
			empty = false
			// split up tokens that are larger than 255 into 255-chunks
			sx := []string{}
			p := 0
			for {
				i, ok := escapedStringOffset(l.Token[p:], 255)
				if !ok {
					return nil, &ParseError{err: errstr, lex: l}
				}
				if i != -1 && p+i != len(l.Token) {
					sx = append(sx, l.Token[p:p+i])
				} else {
					sx = append(sx, l.Token[p:])
					break

				}
				p += i
			}
			s = append(s, sx...)
		case dnslex.Blank:
			if quote {
				// dnslex.Blank can only be seen in between txt parts.
				return nil, &ParseError{err: errstr, lex: l}
			}
		case dnslex.Quote:
			if empty && quote {
				s = append(s, "")
			}
			quote = !quote
			empty = true
		default:
			return nil, &ParseError{err: errstr, lex: l}
		}
		l, _ = c.Next()
	}

	if quote {
		return nil, &ParseError{err: errstr, lex: l}
	}

	return s, nil
}
