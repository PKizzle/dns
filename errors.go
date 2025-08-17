package dns

import "fmt"

// Error represents a DNS error.
type Error struct{ err string }

func (e *Error) Fmt(format string, a ...any) error {
	e.err += fmt.Sprintf(format, a...)
	return e
}

func (e *Error) Error() string { return "dns: " + e.err }

var (
	ErrAlg              = &Error{err: "bad algorithm"}                  // ErrAlg indicates an error with the (DNSSEC) algorithm.
	ErrBuf              = &Error{err: "buffer size too small"}          // ErrBuf indicates that the buffer used is too small for the message.
	ErrFqdn             = &Error{err: "domain must be fully qualified"} // ErrFqdn indicates that a domain name does not have a closing dot.
	ErrName             = &Error{err: "bad domain name"}
	ErrLabel            = &Error{err: "bad label type"}
	ErrID               = &Error{err: "id mismatch"}
	ErrKeyAlg           = &Error{err: "bad key algorithm"} // ErrKeyAlg indicates that the algorithm in the key is not valid.
	ErrKey              = &Error{err: "bad key"}
	ErrKeySize          = &Error{err: "bad key size"}
	ErrLongDomain       = &Error{err: fmt.Sprintf("domain name exceeded %d wire-format octets", maxDomainNameWireOctets)}
	ErrNoTSIG           = &Error{err: "no TSIG signature found"}
	ErrPrivKey          = &Error{err: "bad private key"}
	ErrRcode            = &Error{err: "bad rcode"}
	ErrRRset            = &Error{err: "bad rrset"}
	ErrShortRead        = &Error{err: "short read"}
	ErrSig              = &Error{err: "bad signature"} // ErrSig indicates that a signature can not be cryptographically validated.
	ErrSOA              = &Error{err: "no SOA"}        // ErrSOA indicates that no SOA RR was seen when doing zone transfers.
	ErrOPT              = &Error{err: "unknown OPT code"}
	ErrTime             = &Error{err: "bad time"} // ErrTime indicates a timing error in TSIG authentication.
	ErrTruncatedMessage = &Error{err: "overflow unpacking truncated message"}
	ErrUnpackOverflow   = &Error{err: "overflow unpacking data"}
	ErrTrailingData     = &Error{err: "trailing record rdata"}
	ErrLenData          = &Error{err: "inconsitent rdata length"}
)
