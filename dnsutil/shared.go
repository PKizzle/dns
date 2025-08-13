package dnsutil

import (
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/internal/ddd"
)

// This is copied to zdnsutil.go in the main package to also have access to these functions and not have an
// import cycle.

// Count return the number of labels in the name s.
func Count(s string) (labels int) {
	if s == "." {
		return
	}
	off := 0
	end := false
	for {
		off, end = Next(s, off)
		labels++
		if end {
			return
		}
	}
}

// Next returns the index of the start of the next label in the
// string s starting at offset. A negative offset will cause a panic.
// The bool end is true when the end of the string has been reached.
// Also see [Prev].
func Next(s string, offset int) (i int, end bool) {
	if s == "" {
		return 0, true
	}
	for i = offset; i < len(s)-1; i++ {
		if s[i] != '.' {
			continue
		}
		j := i - 1
		for j >= 0 && s[j] == '\\' {
			j--
		}

		if (j-i)%2 == 0 {
			continue
		}

		return i + 1, false
	}
	return i + 1, true
}

// IsRRset reports whether a set of RRs is a valid RRset as defined by RFC 2181.
// This means the RRs need to have the same type, name, and class.
func IsRRset(rrset []dns.RR) bool {
	if len(rrset) == 0 {
		return false
	}

	base := rrset[0].Header()
	basetype := dns.RRToType(rrset[0])
	for _, rr := range rrset[1:] {
		h := rr.Header()
		htype := dns.RRToType(rr)
		if htype != basetype || h.Class != base.Class || h.Name != base.Name {
			return false
		}
	}

	return true
}

// Fqdn return the fully qualified domain name from s. If s is already fully qualified, it behaves as the identity function.
func Fqdn(s string) string {
	if IsFqdn(s) {
		return s
	}
	return s + "."
}

// IsFqdn checks if a domain name is fully qualified. Note that due the escapes in the names this is not
// completely trivial to establish.
func IsFqdn(s string) bool {
	if s == "." {
		return true
	}
	l := len(s)
	if l < 2 {
		return false
	}
	if s[l-1] != '.' { // no dot in final elements
		return false
	}
	// If we don't have an escape sequence before the final dot, we know it's fully qualified and can return here.
	if s[l-2] != '\\' {
		return true
	}

	// Otherwise we have to check if the dot is escaped or not by checking if there are an odd or even number of escape sequences before the dot.
	i := strings.LastIndexFunc(s[:l-2], func(r rune) bool {
		return r != '\\'
	})
	// TODO: revist! And TEST
	return ((l-2)-i)%2 == 0
}

// Canonical returns the domain name in canonical form. A name in canonical form is lowercase and fully qualified.
// / Only US-ASCII letters are affected. See Section 6.2 in RFC 4034.
func Canonical(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		return r
	}, Fqdn(s))
}

// IsName checks if s is a valid domain name.  Note that non fully qualified domain name is considered valid
// the number of labels. Note that this function is extremely liberal; almost any
// string is a valid domain name as the DNS is 8 bit protocol. It checks if each
// label fits in 63 characters and that the entire name will fit into the 255 octet wire format limit.
func IsName(s string) bool {
	// XXX: The logic in this function was copied from packName and
	// should be kept in sync with that function.

	const lenmsg = 256

	// Each dot ends a segment of the name. Except for escaped dots (\.), which are normal dots.

	var (
		off    int
		begin  int
		wasDot bool
	)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if off+1 > lenmsg {
				return false
			}

			// check for \DDD
			if ddd.Is(s[i+1:]) {
				i += 3
				begin += 3
			} else {
				i++
				begin++
			}

			wasDot = false
		case '.':
			if i == 0 && len(s) > 1 {
				// leading dots are not legal except for the root zone
				return false
			}

			if wasDot {
				// two dots back to back is not legal
				return false
			}
			wasDot = true

			labelLen := i - begin
			if labelLen >= 1<<6 { // top two bits of length must be clear
				return false
			}

			// off can already (we're in a loop) be bigger than lenmsg
			// this happens when a name isn't fully qualified
			off += 1 + labelLen
			if off > lenmsg {
				return false
			}

			begin = i + 1
		default:
			wasDot = false
		}
	}
	return true
}

// SetReply creates a reply message from r. It copies the ID, opcode, rcode and question and sets [m.Response] to true in m
func SetReply(m, r *dns.Msg) *dns.Msg {
	m.ID = r.ID
	m.Response = true
	m.Opcode = r.Opcode
	if m.Opcode == dns.OpcodeQuery {
		m.RecursionDesired = r.RecursionDesired
		m.CheckingDisabled = r.CheckingDisabled
	}
	m.Rcode = dns.RcodeSuccess
	m.Question = r.Question
	return m
}
