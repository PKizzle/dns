package dns

import (
	"encoding/binary"
	"strconv"
)

func (o *ZONEVERSION) parse(c *zlexer, _ string) *ParseError {
	// this parses the output from string:  "8 SOA-SERIAL 1000000000"
	l, _ := c.Next()
	i, e := strconv.ParseUint(l.token, 10, 8)
	if e != nil || l.err {
		return &ParseError{err: "bad ZONEVERSION Labels", lex: l}
	}
	o.Labels = uint8(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	// type, can be TYPEXXX, or SOA-SERIAL - we only accept SOA-SERIAL
	if l.token == "SOA-SERIAL" {
		o.Type = 0
		o.Version = make([]byte, 4)
	}
	c.Next()        // zBlank
	l, _ = c.Next() // zString
	i, e = strconv.ParseUint(l.token, 10, 32)
	if e != nil || l.err {
		return &ParseError{err: "bad ZONEVERSION Version", lex: l}
	}
	binary.BigEndian.PutUint32(o.Version, uint32(i))
	return slurpRemainder(c)
}
