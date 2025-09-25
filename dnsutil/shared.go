package dnsutil

import (
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/internal/ddd"
)

// This is copied to zdnsutil.go in the main package to also have access to these functions and not have an
// import cycle. See dnsutil_generate.go.

// Labels returns the number of labels in the name s.
func Labels(s string) (labels int) {
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

// Prev returns the index of the label when starting from the right and jumping n labels to the left.
// The bool start is true when the start of the string has been overshot. Also see [Next].
func Prev(s string, n int) (i int, start bool) {
	if s == "" {
		return 0, true
	}
	if n == 0 {
		return len(s), false
	}

	l := len(s) - 1
	if s[l] == '.' {
		l--
	}

	for ; l >= 0 && n > 0; l-- {
		if s[l] != '.' {
			continue
		}
		j := l - 1
		for j >= 0 && s[j] == '\\' {
			j--
		}

		if (j-l)%2 == 0 {
			continue
		}

		n--
		if n == 0 {
			return l + 1, false
		}
	}

	return 0, n > 1
}

// IsRRset reports whether a set of RRs is a valid RRset as defined by RFC 2181.
// This means the RRs need to have the same type, name, and class.
func IsRRset(rrset []dns.RR) bool {
	// duplicates... ?
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

// IsFqdn checks if a domain name is fully qualified. Note that due the escapes in names this is not completely trivial to establish.
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
	// XXX: The logic in this function was copied from pack.Name and should be kept in sync with that function.

	const lenmsg = 256

	// Each dot ends a segment of the name. Except for escaped dots (\.), which are normal dots.

	var (
		off    int
		begin  int
		wasDot bool
		escape bool
	)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			escape = !escape
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
			escape = false
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
	if escape {
		return false
	}
	return true
}

// SetReply creates a reply message from r. It copies the ID, opcode, rcode and question, r's Data buffer is not copied.
// In the header the RecursionDesired, CheckingDisabled and Security are copied.
func SetReply(m, r *dns.Msg) *dns.Msg {
	m.ID = r.ID
	m.Response = true
	m.Opcode = r.Opcode
	if m.Opcode == dns.OpcodeQuery {
		m.RecursionDesired = r.RecursionDesired
		m.CheckingDisabled = r.CheckingDisabled
		m.Security = r.Security
	}
	m.Rcode = dns.RcodeSuccess
	m.Question = r.Question
	m.Answer = nil
	m.Ns = nil
	m.Extra = nil
	m.Pseudo = nil
	return m
}

// compareLabel compares a and b while ignoring case. It returns 0 when equal, -1 when a is smaller than b,
// and +1 when a is greater then b. This ends up a compareLabel in the dns package too as generated by
// dnsutil_generate.go.
func compareLabel(a, b string) int {
	for i := range min(len(a), len(b)) {
		ai := a[i]
		bi := b[i]
		if ai >= 'A' && ai <= 'Z' {
			ai |= 'a' - 'A'
		}
		if bi >= 'A' && bi <= 'Z' {
			bi |= 'a' - 'A'
		}
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}

// TimeToString translates the RRSIG's incep. and expir. times to the
// string representation used when printing the record. It takes serial arithmetic (RFC 1982) into account.
func TimeToString(t uint32) string {
	mod := (int64(t)-time.Now().Unix())/MaxSerialIncrement - 1
	if mod < 0 {
		mod = 0
	}
	ti := time.Unix(int64(t)-mod*MaxSerialIncrement, 0).UTC()
	return ti.Format("20060102150405")
}

// StringToTime translates the RRSIG's incep. and expir. times from string values like "20110403154150" to an 32 bit integer.
// It takes serial arithmetic (RFC 1982) into account.
func StringToTime(s string) (uint32, error) {
	t, err := time.Parse("20060102150405", s)
	if err != nil {
		return 0, err
	}
	mod := t.Unix()/MaxSerialIncrement - 1
	if mod < 0 {
		mod = 0
	}
	return uint32(t.Unix() - mod*MaxSerialIncrement), nil
}

// Absolute takes the name and origin and appends the origin to the name. This takes the 1035 presentation
// format into account, i.e. "@" means the origin in name. Absolute will return name if called
// with an empty origin. Name is assumed to be a valid domain name.
func Absolute(name, origin string) string {
	if origin == "" {
		return name
	}
	if name == "@" {
		return origin
	}
	if name == "\n" { // this can happen when a zone is parsed, internal quirk, should not be here...
		return ""
	}
	if IsFqdn(name) {
		return name
	}
	if origin == "." {
		return name + origin
	}
	return name + "." + origin
}
