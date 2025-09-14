package dns

import (
	"fmt"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns/internal/ddd"
)

func sprintName(s string) string {
	var sb strings.Builder

	for i := 0; i < len(s); {
		if s[i] == '.' {
			if sb.Len() != 0 {
				sb.WriteByte('.')
			}
			i++
			continue
		}

		b, n := ddd.Next(s, i)
		if n == 0 {
			// Drop "dangling" incomplete escapes.
			if sb.Len() == 0 {
				return s[:i]
			}
			break
		}
		if ddd.ShouldEscape(b) {
			if sb.Len() == 0 {
				sb.Grow(len(s) * 2)
				sb.WriteString(s[:i])
			}
			sb.WriteByte('\\')
			sb.WriteByte(b)
		} else if b < ' ' || b > '~' { // unprintable, use \DDD
			if sb.Len() == 0 {
				sb.Grow(len(s) * 2)
				sb.WriteString(s[:i])
			}
			sb.WriteString(ddd.Escape(b))
		} else {
			if sb.Len() != 0 {
				sb.WriteByte(b)
			}
		}
		i += n
	}
	if sb.Len() == 0 {
		return s
	}
	return sb.String()
}

func sprintTxtOctet(s string) string {
	var sb strings.Builder
	sb.Grow(2 + len(s))
	sb.WriteByte('"')
	for i := 0; i < len(s); {
		if i+1 < len(s) && s[i] == '\\' && s[i+1] == '.' {
			sb.WriteString(s[i : i+2])
			i += 2
			continue
		}

		b, n := ddd.Next(s, i)
		if n == 0 {
			i++ // dangling back slash
		} else {
			writeTXTStringByte(&sb, b)
		}
		i += n
	}
	sb.WriteByte('"')
	return sb.String()
}

func sprintTxt(txt []string) string {
	var sb strings.Builder
	for i, s := range txt {
		sb.Grow(3 + len(s))
		if i > 0 {
			sb.WriteString(` "`)
		} else {
			sb.WriteByte('"')
		}
		for j := 0; j < len(s); {
			b, n := ddd.Next(s, j)
			if n == 0 {
				break
			}
			writeTXTStringByte(&sb, b)
			j += n
		}
		sb.WriteByte('"')
	}
	return sb.String()
}

func writeTXTStringByte(s *strings.Builder, b byte) {
	switch {
	case b == '"' || b == '\\':
		s.WriteByte('\\')
		s.WriteByte(b)
	case b < ' ' || b > '~':
		s.WriteString(ddd.Escape(b))
	default:
		s.WriteByte(b)
	}
}

func sprintType(t uint16) string {
	if t1, ok := TypeToString[uint16(t)]; ok {
		return t1
	}
	return "TYPE" + strconv.Itoa(int(t))
}

func sprintCode(t uint16) string {
	if t1, ok := CodeToString[uint16(t)]; ok {
		return t1
	}
	return "CODE" + strconv.Itoa(int(t))
}

func sprintClass(c uint16) string {
	if s, ok := ClassToString[uint16(c)]; ok {
		return s
	}
	return "CLASS" + strconv.Itoa(int(c))
}

func sprintRcode(r uint16) string {
	if r1, ok := RcodeToString[r]; ok {
		return r1
	}
	return "RCODE" + strconv.Itoa(int(r))
}

func sprintOpcode(o uint8) string {
	if o1, ok := OpcodeToString[o]; ok {
		return o1
	}
	return "OPCODE" + strconv.Itoa(int(o))
}

// saltToString converts a NSECX salt to uppercase and returns "-" when it is empty.
func saltToString(s string) string {
	if s == "" {
		return "-"
	}
	return strings.ToUpper(s)
}

func euiToString(eui uint64, bits int) (hex string) {
	switch bits {
	case 64:
		hex = fmt.Sprintf("%16.16x", eui)
		hex = hex[0:2] + "-" + hex[2:4] + "-" + hex[4:6] + "-" + hex[6:8] +
			"-" + hex[8:10] + "-" + hex[10:12] + "-" + hex[12:14] + "-" + hex[14:16]
	case 48:
		hex = fmt.Sprintf("%12.12x", eui)
		hex = hex[0:2] + "-" + hex[2:4] + "-" + hex[4:6] + "-" + hex[6:8] +
			"-" + hex[8:10] + "-" + hex[10:12]
	}
	return
}

// sprintHeader creates a strings.Builder, write the header to it, plus an extra tab and returns the builder.
func sprintHeader(rr RR) *strings.Builder {
	sb := strings.Builder{}
	sb.WriteString(sprintName(rr.Header().Name))
	sb.WriteByte('\t')

	sb.WriteString(strconv.FormatInt(int64(rr.Header().TTL), 10))
	sb.WriteByte('\t')

	sb.WriteString(sprintClass(rr.Header().Class))
	sb.WriteByte('\t')

	rrtype := rr.Header().t
	if rrtype == 0 {
		rrtype = RRToType(rr)
	}
	sb.WriteString(sprintType(rrtype))
	sb.WriteByte('\t')
	return &sb
}

// must look just enough so parsing from text will also work.
func sprintOptionHeader(rr EDNS0) *strings.Builder {
	sb := strings.Builder{}
	sb.WriteByte('.')
	sb.WriteByte('\t')

	sb.WriteByte('\t') // skip TTL

	sb.WriteString(sprintClass(rr.Header().Class))
	sb.WriteByte('\t')

	rrcode := RRToCode(rr)
	sb.WriteString(sprintCode(rrcode))
	sb.WriteByte('\t')
	return &sb
}

// sprintData write the rdata to sb with spaces between the elements
func sprintData(sb *strings.Builder, sx ...string) {
	for i, s := range sx {
		sb.WriteString(s)
		if i < len(sx)-1 {
			sb.WriteByte(' ')
		}
	}
}

func splitN(s string, n int) []string {
	if len(s) < n {
		return []string{s}
	}
	sx := []string{}
	p, i := 0, n
	for {
		if i <= len(s) {
			sx = append(sx, s[p:i])
		} else {
			sx = append(sx, s[p:])
			break

		}
		p, i = p+n, i+n
	}

	return sx
}
