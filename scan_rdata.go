package dns

import (
	"strconv"

	"codeberg.org/miekg/dns/internal/dnslex"
	"codeberg.org/miekg/dns/rdata"
)

func parseMX(rd *rdata.MX, c *dnslex.Lexer, o string) *ParseError {
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.Token, 10, 16)
	if e != nil || l.Err {
		return &ParseError{err: "bad MX Pref", lex: l}
	}
	rd.Preference = uint16(i)

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Mx = l.Token

	name := dnsutilAbsolute(l.Token, o)
	if l.Err || name == "" {
		return &ParseError{err: "bad MX Mx", lex: l}
	}
	rd.Mx = name
	return toParseError(dnslex.Remainder(c))
}
