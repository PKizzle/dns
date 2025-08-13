package dns

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"golang.org/x/crypto/cryptobyte"
)

// Code option codes.
const (
	CodeNone         uint16 = 0x0
	CodeLLQ          uint16 = 0x1    // Long lived queries: http://tools.ietf.org/html/draft-sekar-dns-llq-01
	CodeUL           uint16 = 0x2    // Update lease draft: http://files.dns-sd.org/draft-sekar-dns-ul.txt
	CodeNSID         uint16 = 0x3    // Nsid (See RFC 5001)
	CodeESU          uint16 = 0x4    // ENUM Source-URI draft: https://datatracker.ietf.org/doc/html/draft-kaplan-enum-source-uri-00
	CodeDAU          uint16 = 0x5    // DNSSEC Algorithm Understood
	CodeDHU          uint16 = 0x6    // DS Hash Understood
	CodeN3U          uint16 = 0x7    // NSEC3 Hash Understood
	CodeSUBNET       uint16 = 0x8    // Client-subnet (See RFC 7871)
	CodeEXPIRE       uint16 = 0x9    // Expire
	CodeCOOKIE       uint16 = 0xa    // Cookie
	CodeTCPKEEPALIVE uint16 = 0xb    // Tcp keep alive (See RFC 7828)
	CodePADDING      uint16 = 0xc    // Padding (See RFC 7830)
	CodeEDE          uint16 = 0xf    // Extended DNS errors (See RFC 8914)
	CodeLOCALSTART   uint16 = 0xFDE9 // Beginning of range reserved for local/experimental use (See RFC 6891)
	CodeLOCALEND     uint16 = 0xFFFE // End of range reserved for local/experimental use (See RFC 6891)
)

// Extended DNS Error Codes (RFC 8914).
const (
	ExtendedErrorOther uint16 = iota
	ExtendedErrorUnsupportedDNSKEYAlgorithm
	ExtendedErrorUnsupportedDSDigestType
	ExtendedErrorStaleAnswer
	ExtendedErrorForgedAnswer
	ExtendedErrorDNSSECIndeterminate
	ExtendedErrorDNSBogus
	ExtendedErrorSignatureExpired
	ExtendedErrorSignatureNotYetValid
	ExtendedErrorDNSKEYMissing
	ExtendedErrorRRSIGsMissing
	ExtendedErrorNoZoneKeyBitSet
	ExtendedErrorNSECMissing
	ExtendedErrorCachedError
	ExtendedErrorNotReady
	ExtendedErrorBlocked
	ExtendedErrorCensored
	ExtendedErrorFiltered
	ExtendedErrorProhibited
	ExtendedErrorStaleNXDOMAINAnswer
	ExtendedErrorNotAuthoritative
	ExtendedErrorNotSupported
	ExtendedErrorNoReachableAuthority
	ExtendedErrorNetworkError
	ExtendedErrorInvalidData
)

// ExtendedErrorToString maps extended error info codes to a human readable description.
var ExtendedErrorToString = map[uint16]string{
	ExtendedErrorOther:                      "Other",
	ExtendedErrorUnsupportedDNSKEYAlgorithm: "Unsupported DNSKEY Algorithm",
	ExtendedErrorUnsupportedDSDigestType:    "Unsupported DS Digest Type",
	ExtendedErrorStaleAnswer:                "Stale Answer",
	ExtendedErrorForgedAnswer:               "Forged Answer",
	ExtendedErrorDNSSECIndeterminate:        "DNSSEC Indeterminate",
	ExtendedErrorDNSBogus:                   "DNSSEC Bogus",
	ExtendedErrorSignatureExpired:           "Signature Expired",
	ExtendedErrorSignatureNotYetValid:       "Signature Not Yet Valid",
	ExtendedErrorDNSKEYMissing:              "DNSKEY Missing",
	ExtendedErrorRRSIGsMissing:              "RRSIGs Missing",
	ExtendedErrorNoZoneKeyBitSet:            "No Zone Key Bit Set",
	ExtendedErrorNSECMissing:                "NSEC Missing",
	ExtendedErrorCachedError:                "Cached Error",
	ExtendedErrorNotReady:                   "Not Ready",
	ExtendedErrorBlocked:                    "Blocked",
	ExtendedErrorCensored:                   "Censored",
	ExtendedErrorFiltered:                   "Filtered",
	ExtendedErrorProhibited:                 "Prohibited",
	ExtendedErrorStaleNXDOMAINAnswer:        "Stale NXDOMAIN Answer",
	ExtendedErrorNotAuthoritative:           "Not Authoritative",
	ExtendedErrorNotSupported:               "Not Supported",
	ExtendedErrorNoReachableAuthority:       "No Reachable Authority",
	ExtendedErrorNetworkError:               "Network Error",
	ExtendedErrorInvalidData:                "Invalid Data",
}

// StringToExtendedError is a map from human readable descriptions to extended error info codes.
var StringToExtendedError = reverseInt16(ExtendedErrorToString)

const tlv = 4

func unpackOptionCode(option EDNS0, s *cryptobyte.String) error {
	switch x := option.(type) {
	case *LLQ:
		return x.unpack(s)
	case *NSID:
		return x.unpack(s)
	case *PADDING:
		return x.unpack(s)
	case *EDE:
		return x.unpack(s)
	case *COOKIE:
		return x.unpack(s)
	}
	// Coder() check, abuse Type()?
	return fmt.Errorf("dns: no option unpack defined")
}

func packOptionCode(option EDNS0, msg []byte, off int) (int, error) {
	switch x := option.(type) {
	case *LLQ:
		return x.pack(msg, off)
	case *NSID:
		return x.pack(msg, off)
	case *PADDING:
		return x.pack(msg, off)
	case *EDE:
		return x.pack(msg, off)
	case *COOKIE:
		return x.pack(msg, off)
	}
	// Coder() check, abuse Type()?
	return 0, fmt.Errorf("dns: no option pack defined")
}

// LLQ stands for Long Lived Queries: http://tools.ietf.org/html/draft-sekar-dns-llq-01
// Implemented for completeness, as the EDNS0 type code is assigned.
type LLQ struct {
	Version   uint16
	Opcode    uint16
	Error     uint16
	ID        uint64
	LeaseLife uint32
}

func (o *LLQ) Len() int { return tlv + 18 }
func (o *LLQ) String() string {
	sb := sprintOptionHeader(o)
	sprintData(sb, strconv.FormatUint(uint64(o.Version), 10), strconv.FormatUint(uint64(o.Opcode), 10),
		strconv.FormatUint(uint64(o.Error), 10), strconv.FormatUint(o.ID, 10),
		strconv.FormatUint(uint64(o.LeaseLife), 10))
	return sb.String()
}

// The Cookie option is used to add a DNS Cookie to a message.
//
// The Cookie field consists out of a client cookie (RFC 7873 Section 4), that is
// always 8 bytes. It may then optionally be followed by the server cookie. The server
// cookie is of variable length, 8 to a maximum of 32 bytes. In other words:
//
//	cCookie := o.Cookie[:16]
//	sCookie := o.Cookie[16:]
//
// There is no guarantee that the Cookie string has a specific length.
type COOKIE struct {
	Cookie string `dns:"hex"`
}

func (o *COOKIE) Len() int { return tlv + len(o.Cookie) }
func (o *COOKIE) String() string {
	sb := sprintOptionHeader(o)
	sb.WriteString(o.Cookie)
	return sb.String()
}

// NSID EDNS0 option is used to retrieve a nameserver identifier. When sending a request Nsid must be empty.
// The identifier is an opaque string encoded as hex.
type NSID struct {
	Nsid string `dns:"hex"`
}

func (o *NSID) Len() int { return tlv + len(o.Nsid)/2 }
func (o *NSID) String() string {
	sb := sprintOptionHeader(o)
	sb.WriteString(o.Nsid)
	if x, err := hex.DecodeString(o.Nsid); err == nil { // == nil
		sb.WriteString(" ; (\"")
		sb.Write(x)
		sb.WriteString("\")")
	}
	return sb.String()
}

// PADDING option is used to add padding to a request/response. The default value of padding SHOULD be 0x0 but
// other values MAY be used.
type PADDING struct {
	Padding string `dns:"octet"`
}

func (o *PADDING) Len() int       { return tlv + len(o.Padding) }
func (o *PADDING) String() string { return "" } // tODO miek

// EDE option is used to return additional information about the cause of DNS errors.
type EDE struct {
	InfoCode  uint16
	ExtraText string
}

func (o *EDE) Len() int { return tlv + 2 + len(o.ExtraText) }
func (o *EDE) String() string {
	// strings.Builder TODO: miek
	info := strconv.FormatUint(uint64(o.InfoCode), 10)
	if s, ok := ExtendedErrorToString[o.InfoCode]; ok {
		info += fmt.Sprintf(" (%s)", s)
	}
	return fmt.Sprintf("%s: (%s)", info, o.ExtraText)
}
