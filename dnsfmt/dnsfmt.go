// Package dnsfmt deals with formatting of DNS records.
package dnsfmt

// logical equivalents exist in ../string.go that are used internally. Due to cyclic deps we can import and
// use these from the dns package.

import (
	"strconv"
	"strings"
	"sync"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/internal/ddd"
)

// Header returns the header of the RR as a formatted string.
func Header(rr dns.RR) string {
	sb := builderPool.Get()

	sb.WriteString(Name(rr.Header().Name))
	sb.WriteByte('\t')

	sb.WriteString(strconv.FormatInt(int64(rr.Header().TTL), 10))
	sb.WriteByte('\t')

	sb.WriteString(dnsutil.ClassToString(rr.Header().Class))
	sb.WriteByte('\t')

	rrtype := dns.RRToType(rr)
	sb.WriteString(dnsutil.TypeToString(rrtype))
	sb.WriteByte('\t')
	s := sb.String()
	builderPool.Put(sb)
	return s
}

// OptionHeader returns the header of the EDNS0 RR as a formatted string.
func OptionHeader(rr dns.EDNS0) string {
	sb := builderPool.Get()

	sb.WriteByte('.')
	sb.WriteByte('\t')

	sb.WriteByte('\t') // skip TTL

	sb.WriteString(dnsutil.ClassToString(rr.Header().Class))
	sb.WriteByte('\t')

	code := dns.RRToCode(rr)
	sb.WriteString(dnsutil.CodeToString(code))
	sb.WriteByte('\t')
	s := sb.String()
	builderPool.Put(sb)
	return s
}

// Name returns the string format of a domain name.
func Name(s string) string {
	sb := builderPool.Get()
	defer builderPool.Put(sb)

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

// builderPooler is a pool used by the String methods.
type builderPooler struct {
	sync.Pool
}

func (s *builderPooler) Get() strings.Builder   { return s.Pool.Get().(strings.Builder) }
func (s *builderPooler) Put(sb strings.Builder) { sb.Reset(); s.Pool.Put(sb) }

var builderPool = &builderPooler{Pool: sync.Pool{New: func() any { return strings.Builder{} }}}
