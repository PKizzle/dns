package dns

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns/deleg"
	"codeberg.org/miekg/dns/svcb"
)

// Packet formats

// Wire constants and supported types.
const (
	// valid RR types and question types

	TypeNone       uint16 = 0
	TypeA          uint16 = 1
	TypeNS         uint16 = 2
	TypeMD         uint16 = 3
	TypeMF         uint16 = 4
	TypeCNAME      uint16 = 5
	TypeSOA        uint16 = 6
	TypeMB         uint16 = 7
	TypeMG         uint16 = 8
	TypeMR         uint16 = 9
	TypeNULL       uint16 = 10
	TypePTR        uint16 = 12
	TypeHINFO      uint16 = 13
	TypeMINFO      uint16 = 14
	TypeMX         uint16 = 15
	TypeTXT        uint16 = 16
	TypeRP         uint16 = 17
	TypeAFSDB      uint16 = 18
	TypeX25        uint16 = 19
	TypeISDN       uint16 = 20
	TypeRT         uint16 = 21
	TypeNSAPPTR    uint16 = 23
	TypeSIG        uint16 = 24
	TypeKEY        uint16 = 25
	TypePX         uint16 = 26
	TypeGPOS       uint16 = 27
	TypeAAAA       uint16 = 28
	TypeLOC        uint16 = 29
	TypeNXT        uint16 = 30
	TypeEID        uint16 = 31
	TypeNIMLOC     uint16 = 32
	TypeSRV        uint16 = 33
	TypeATMA       uint16 = 34
	TypeNAPTR      uint16 = 35
	TypeKX         uint16 = 36
	TypeCERT       uint16 = 37
	TypeDNAME      uint16 = 39
	TypeOPT        uint16 = 41
	TypeAPL        uint16 = 42 // Not implemented.
	TypeDS         uint16 = 43
	TypeSSHFP      uint16 = 44
	TypeIPSECKEY   uint16 = 45 // Not implemented.
	TypeRRSIG      uint16 = 46
	TypeNSEC       uint16 = 47
	TypeDNSKEY     uint16 = 48
	TypeDHCID      uint16 = 49
	TypeNSEC3      uint16 = 50
	TypeNSEC3PARAM uint16 = 51
	TypeTLSA       uint16 = 52
	TypeSMIMEA     uint16 = 53
	TypeHIP        uint16 = 55
	TypeNINFO      uint16 = 56
	TypeRKEY       uint16 = 57
	TypeTALINK     uint16 = 58
	TypeCDS        uint16 = 59
	TypeCDNSKEY    uint16 = 60
	TypeOPENPGPKEY uint16 = 61
	TypeCSYNC      uint16 = 62
	TypeZONEMD     uint16 = 63
	TypeSVCB       uint16 = 64
	TypeHTTPS      uint16 = 65
	TypeSPF        uint16 = 99
	TypeUINFO      uint16 = 100
	TypeUID        uint16 = 101
	TypeGID        uint16 = 102
	TypeUNSPEC     uint16 = 103
	TypeNID        uint16 = 104
	TypeL32        uint16 = 105
	TypeL64        uint16 = 106
	TypeLP         uint16 = 107
	TypeEUI48      uint16 = 108
	TypeEUI64      uint16 = 109
	TypeNXNAME     uint16 = 128
	TypeURI        uint16 = 256
	TypeCAA        uint16 = 257
	TypeAVC        uint16 = 258
	TypeAMTRELAY   uint16 = 260 // Not implemented.
	TypeRESINFO    uint16 = 261

	TypeTKEY uint16 = 249
	TypeTSIG uint16 = 250

	// Valid question types only.
	TypeIXFR  uint16 = 251
	TypeAXFR  uint16 = 252
	TypeMAILB uint16 = 253
	TypeMAILA uint16 = 254
	TypeANY   uint16 = 255

	TypeTA       uint16 = 32768
	TypeDLV      uint16 = 32769
	TypeDELEG    uint16 = 65432 // Provisional type
	TypeDELEGI   uint16 = 65433 // Provisional type
	TypeReserved uint16 = 65535

	// valid question classes only.
	ClassINET   = 1
	ClassCSNET  = 2
	ClassCHAOS  = 3
	ClassHESIOD = 4
	ClassNONE   = 254
	ClassANY    = 255

	// Message Response Codes, see https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
	RcodeSuccess                = 0  // NoError   - No Error                          [DNS]
	RcodeFormatError            = 1  // FormErr   - Format Error                      [DNS]
	RcodeServerFailure          = 2  // ServFail  - Server Failure                    [DNS]
	RcodeNameError              = 3  // NXDomain  - Non-Existent Domain               [DNS]
	RcodeNotImplemented         = 4  // NotImp    - Not Implemented                   [DNS]
	RcodeRefused                = 5  // Refused   - Query Refused                     [DNS]
	RcodeYXDomain               = 6  // YXDomain  - Name Exists when it should not    [DNS Update]
	RcodeYXRrset                = 7  // YXRRSet   - RR Set Exists when it should not  [DNS Update]
	RcodeNXRrset                = 8  // NXRRSet   - RR Set that should exist does not [DNS Update]
	RcodeNotAuth                = 9  // NotAuth   - Server Not Authoritative for zone [DNS Update]
	RcodeNotZone                = 10 // NotZone   - Name not contained in zone        [DNS Update/TSIG]
	RcodeStatefulNotImplemented = 11 // DSOTYPENI - DSO-TYPE Not Implemented [DSO]    [DSO]
	RcodeBadSig                 = 16 // BADSIG    - TSIG Signature Failure            [TSIG]
	RcodeBadVers                = 16 // BADVERS   - Bad OPT Version                   [EDNS0]
	RcodeBadKey                 = 17 // BADKEY    - Key not recognized                [TSIG]
	RcodeBadTime                = 18 // BADTIME   - Signature out of time window      [TSIG]
	RcodeBadMode                = 19 // BADMODE   - Bad TKEY Mode                     [TKEY]
	RcodeBadName                = 20 // BADNAME   - Duplicate key name                [TKEY]
	RcodeBadAlg                 = 21 // BADALG    - Algorithm not supported           [TKEY]
	RcodeBadTrunc               = 22 // BADTRUNC  - Bad Truncation                    [TSIG]
	RcodeBadCookie              = 23 // BADCOOKIE - Bad/missing Server Cookie         [DNS Cookies]

	// Message Opcodes. There is no 3.
	OpcodeQuery    = 0
	OpcodeIQuery   = 1
	OpcodeStatus   = 2
	OpcodeNotify   = 4
	OpcodeUpdate   = 5
	OpcodeStateful = 6
)

// Names for things inside RRs should be RR-name (all capitals) and than snakecase the rest.

// Used in ZONEMD, RFC 8976.
const (
	ZONEMDSchemeSimple = 1

	ZONEMDHashSHA384 = 1
	ZONEMDHashSHA512 = 2
)

// Used in IPSEC, RFC 4025, Section 2.3.
const (
	IPSECGatewayNone uint8 = iota
	IPSECGatewayIPv4
	IPSECGatewayIPv6
	IPSECGatewayHost
)

// Used in AMTRELAY, RFC 8777, Section 4.2.3.
const (
	AMTRELAYNone = IPSECGatewayNone
	AMTRELAYIPv4 = IPSECGatewayIPv4
	AMTRELAYIPv6 = IPSECGatewayIPv6
	AMTRELAYHost = IPSECGatewayHost
)

// header is the wire format for the DNS packet header.
type header struct {
	ID                                 uint16
	Bits                               uint16
	Qdcount, Ancount, Nscount, Arcount uint16
}

const (
	// Header.Bits
	_QR = 1 << 15 // query/response (response=1)
	_AA = 1 << 10 // authoritative
	_TC = 1 << 9  // truncated
	_RD = 1 << 8  // recursion desired
	_RA = 1 << 7  // recursion available
	_Z  = 1 << 6  // Z
	_AD = 1 << 5  // authenticated data
	_CD = 1 << 4  // checking disabled

	// EDNS0 OPT "Header.Bits", these are placed directoy in a *Msg in this impl.
	_DO = 1 << 15 // DNSSEC OK
	_CO = 1 << 14 // Compact Answers OK
	_DE = 1 << 13 // DELEG OK
)

// Various constants used in the LOC RR. See RFC 1876.
const (
	LOCEquator       = 1 << 31 // RFC 1876, Section 2.
	LOCPrimemeridian = 1 << 31 // RFC 1876, Section 2.
	LOCHours         = 60 * 1000
	LOCDegrees       = 60 * LOCHours
	LOCAltitudebase  = 100000
)

// Different Certificate Types, see RFC 4398, Section 2.1
const (
	CertPKIX = 1 + iota
	CertSPKI
	CertPGP
	CertIPIX
	CertISPKI
	CertIPGP
	CertACPKIX
	CertIACPKIX
	CertURI = 253
	CertOID = 254
)

// CertTypeToString converts the Cert Type to its string representation.
// See RFC 4398 and RFC 6944.
var CertTypeToString = map[uint16]string{
	CertPKIX:    "PKIX",
	CertSPKI:    "SPKI",
	CertPGP:     "PGP",
	CertIPIX:    "IPIX",
	CertISPKI:   "ISPKI",
	CertIPGP:    "IPGP",
	CertACPKIX:  "ACPKIX",
	CertIACPKIX: "IACPKIX",
	CertURI:     "URI",
	CertOID:     "OID",
}

// Prefix for IPv4 encoded as IPv6 address
const ipv4InIPv6Prefix = "::ffff:"

// NULL RR. See RFC 1035.
type NULL struct {
	Hdr  Header
	Null string `dns:"any"`
}

func (rr *NULL) String() string {
	// There is no presentation format; prefix string with a comment.
	return ";" + rr.Hdr.String() + rr.Null
}

func (*NULL) parse(c *zlexer, origin string) *ParseError {
	return &ParseError{err: "NULL records do not have a presentation format"}
}

// NXNAME is a meta record. See https://www.iana.org/go/draft-ietf-dnsop-compact-denial-of-existence-04
// Reference: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
type NXNAME struct {
	Hdr Header
	// Does not have any rdata
}

func (rr *NXNAME) String() string { return rr.Hdr.String() }

func (*NXNAME) parse(c *zlexer, origin string) *ParseError {
	return &ParseError{err: "NXNAME records do not have a presentation format"}
}

// CNAME RR. See RFC 1034.
type CNAME struct {
	Hdr    Header
	Target string `dns:"cdomain-name"`
}

func (rr *CNAME) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.Target)
	return sb.String()
}

// HINFO RR. See RFC 1034.
type HINFO struct {
	Hdr Header
	Cpu string
	Os  string
}

func (rr *HINFO) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(sprintTxt([]string{rr.Cpu, rr.Os}))
	return sb.String()
}

// MB RR. See RFC 1035.
type MB struct {
	Hdr Header
	Mb  string `dns:"cdomain-name"`
}

func (rr *MB) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(sprintName(rr.Mb))
	return sb.String()
}

// MG RR. See RFC 1035.
type MG struct {
	Hdr Header
	Mg  string `dns:"cdomain-name"`
}

func (rr *MG) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(sprintName(rr.Mg))
	return sb.String()
}

// MINFO RR. See RFC 1035.
type MINFO struct {
	Hdr   Header
	Rmail string `dns:"cdomain-name"`
	Email string `dns:"cdomain-name"`
}

func (rr *MINFO) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, sprintName(rr.Rmail), sprintName(rr.Email))
	return sb.String()
}

// MR RR. See RFC 1035.
type MR struct {
	Hdr Header
	Mr  string `dns:"cdomain-name"`
}

func (rr *MR) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(sprintName(rr.Mr))
	return sb.String()
}

// MF RR. See RFC 1035.
type MF struct {
	Hdr Header
	Mf  string `dns:"cdomain-name"`
}

func (rr *MF) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(sprintName(rr.Mf))
	return sb.String()
}

// MD RR. See RFC 1035.
type MD struct {
	Hdr Header
	Md  string `dns:"cdomain-name"`
}

func (rr *MD) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(sprintName(rr.Md))
	return sb.String()
}

// MX RR. See RFC 1035.
type MX struct {
	Hdr        Header
	Preference uint16
	Mx         string `dns:"cdomain-name"`
}

func (rr *MX) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Preference)), sprintName(rr.Mx))
	return sb.String()
}

// AFSDB RR. See RFC 1183.
type AFSDB struct {
	Hdr      Header
	Subtype  uint16
	Hostname string `dns:"domain-name"`
}

func (rr *AFSDB) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Subtype)), sprintName(rr.Hostname))
	return sb.String()
}

// X25 RR. See RFC 1183, Section 3.1.
type X25 struct {
	Hdr         Header
	PSDNAddress string
}

func (rr *X25) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.PSDNAddress)
	return sb.String()
}

// ISDN RR. See RFC 1183, Section 3.2.
type ISDN struct {
	Hdr        Header
	Address    string
	SubAddress string
}

func (rr *ISDN) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(sprintTxt([]string{rr.Address, rr.SubAddress}))
	return sb.String()
}

// RT RR. See RFC 1183, Section 3.3.
type RT struct {
	Hdr        Header
	Preference uint16
	Host       string `dns:"domain-name"` // RFC 3597 prohibits compressing records not defined in RFC 1035.
}

func (rr *RT) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Preference)), sprintName(rr.Host))
	return sb.String()
}

// NS RR. See RFC 1035.
type NS struct {
	Hdr Header
	Ns  string `dns:"cdomain-name"`
}

func (rr *NS) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(sprintName(rr.Ns))
	return sb.String()
}

// PTR RR. See RFC 1035.
type PTR struct {
	Hdr Header
	Ptr string `dns:"cdomain-name"`
}

func (rr *PTR) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(sprintName(rr.Ptr))
	return sb.String()
}

// RP RR. See RFC 1138, Section 2.2.
type RP struct {
	Hdr  Header
	Mbox string `dns:"domain-name"`
	Txt  string `dns:"domain-name"`
}

func (rr *RP) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, sprintName(rr.Mbox), sprintName(rr.Txt))
	return sb.String()
}

// SOA RR. See RFC 1035.
type SOA struct {
	Hdr     Header
	Ns      string `dns:"cdomain-name"`
	Mbox    string `dns:"cdomain-name"`
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minttl  uint32
}

func (rr *SOA) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, sprintName(rr.Ns), sprintName(rr.Mbox),
		strconv.FormatInt(int64(rr.Serial), 10),
		strconv.FormatInt(int64(rr.Refresh), 10),
		strconv.FormatInt(int64(rr.Retry), 10),
		strconv.FormatInt(int64(rr.Expire), 10),
		strconv.FormatInt(int64(rr.Minttl), 10))
	return sb.String()
}

// TXT RR. See RFC 1035.
type TXT struct {
	Hdr Header
	Txt []string `dns:"txt"`
}

func (rr *TXT) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(sprintTxt(rr.Txt))
	return sb.String()
}

// SPF RR. See RFC 4408, Section 3.1.1.
type SPF struct {
	Hdr Header
	Txt []string `dns:"txt"`
}

func (rr *SPF) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(sprintTxt(rr.Txt))
	return sb.String()
}

// AVC RR. See https://www.iana.org/assignments/dns-parameters/AVC/avc-completed-template.
type AVC struct {
	Hdr Header
	Txt []string `dns:"txt"`
}

func (rr *AVC) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(sprintTxt(rr.Txt))
	return sb.String()
}

// SRV RR. See RFC 2782.
type SRV struct {
	Hdr      Header
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string `dns:"domain-name"`
}

func (rr *SRV) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Priority)),
		strconv.Itoa(int(rr.Weight)),
		strconv.Itoa(int(rr.Port)), sprintName(rr.Target))
	return sb.String()
}

// NAPTR RR. See RFC 2915.
type NAPTR struct {
	Hdr         Header
	Order       uint16
	Preference  uint16
	Flags       string
	Service     string
	Regexp      string
	Replacement string `dns:"domain-name"`
}

func (rr *NAPTR) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Order)), strconv.Itoa(int(rr.Preference)))

	sb.WriteByte(' ')
	sb.WriteByte('"')
	sb.WriteString(rr.Flags)
	sb.WriteByte('"')

	sb.WriteByte(' ')
	sb.WriteByte('"')
	sb.WriteString(rr.Service)
	sb.WriteByte('"')

	sb.WriteByte(' ')
	sb.WriteByte('"')
	sb.WriteString(rr.Regexp)
	sb.WriteByte('"')
	sb.WriteByte(' ')

	sb.WriteString(rr.Replacement)
	return sb.String()
}

// CERT RR. See RFC 4398.
type CERT struct {
	Hdr         Header
	Type        uint16
	KeyTag      uint16
	Algorithm   uint8
	Certificate string `dns:"base64"`
}

func (rr *CERT) String() string {
	sb := sprintHeader(rr)
	if certtype, ok := CertTypeToString[rr.Type]; !ok {
		sb.WriteString(strconv.Itoa(int(rr.Type)))
	} else {
		sb.WriteString(certtype)
	}

	sb.WriteByte(' ')
	sb.WriteString(strconv.Itoa(int(rr.KeyTag)))
	sb.WriteByte(' ')

	if algorithm, ok := AlgorithmToString[rr.Algorithm]; ok {
		sb.WriteString(algorithm)
	} else {
		sb.WriteString(strconv.Itoa(int(rr.Algorithm)))
	}
	sb.WriteByte(' ')

	sb.WriteString(rr.Certificate)
	return sb.String()
}

// DNAME RR. See RFC 2672.
type DNAME struct {
	Hdr    Header
	Target string `dns:"domain-name"`
}

func (rr *DNAME) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(sprintName(rr.Target))
	return sb.String()
}

// A RR. See RFC 1035.
type A struct {
	Hdr Header
	A   net.IP `dns:"a"`
}

func (rr *A) String() string {
	sb := sprintHeader(rr)
	if rr.A == nil {
		return sb.String()
	}
	sb.WriteString(rr.A.String())
	return sb.String()
}

// AAAA RR. See RFC 3596.
type AAAA struct {
	Hdr  Header
	AAAA net.IP `dns:"aaaa"`
}

func (rr *AAAA) String() string {
	sb := sprintHeader(rr)
	if rr.AAAA == nil {
		return sb.String()
	}

	if rr.AAAA.To4() != nil {
		sb.WriteString(ipv4InIPv6Prefix)
		sb.WriteString(rr.AAAA.String())
		return sb.String()
	}

	sb.WriteString(rr.AAAA.String())
	return sb.String()
}

// PX RR. See RFC 2163.
type PX struct {
	Hdr        Header
	Preference uint16
	Map822     string `dns:"domain-name"`
	Mapx400    string `dns:"domain-name"`
}

func (rr *PX) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Preference)), sprintName(rr.Map822), sprintName(rr.Mapx400))
	return sb.String()
}

// GPOS RR. See RFC 1712.
type GPOS struct {
	Hdr       Header
	Longitude string
	Latitude  string
	Altitude  string
}

func (rr *GPOS) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, rr.Longitude, rr.Latitude, rr.Altitude)
	return sb.String()
}

// LOC RR. See RFC 1876.
type LOC struct {
	Hdr       Header
	Version   uint8
	Size      uint8
	HorizPre  uint8
	VertPre   uint8
	Latitude  uint32
	Longitude uint32
	Altitude  uint32
}

// cmToM takes a cm value expressed in RFC 1876 SIZE mantissa/exponent
// format and returns a string in m (two decimals for the cm).
func cmToM(x uint8) string {
	m := x & 0xf0 >> 4
	e := x & 0x0f

	if e < 2 {
		if e == 1 {
			m *= 10
		}

		return fmt.Sprintf("0.%02d", m)
	}

	s := fmt.Sprintf("%d", m)
	for e > 2 {
		s += "0"
		e--
	}
	return s
}

func (rr *LOC) String() string {
	sb := sprintHeader(rr)

	lat := rr.Latitude
	ns := "N"
	if lat > LOCEquator {
		lat = lat - LOCEquator
	} else {
		ns = "S"
		lat = LOCEquator - lat
	}
	h := lat / LOCDegrees
	lat = lat % LOCDegrees
	m := lat / LOCHours
	lat = lat % LOCHours

	sb.WriteString(fmt.Sprintf("%02d %02d %0.3f %s ", h, m, float64(lat)/1000, ns))

	lon := rr.Longitude
	ew := "E"
	if lon > LOCPrimemeridian {
		lon = lon - LOCPrimemeridian
	} else {
		ew = "W"
		lon = LOCPrimemeridian - lon
	}
	h = lon / LOCDegrees
	lon = lon % LOCDegrees
	m = lon / LOCHours
	lon = lon % LOCHours

	sb.WriteString(fmt.Sprintf("%02d %02d %0.3f %s ", h, m, float64(lon)/1000, ew))

	alt := float64(rr.Altitude) / 100
	alt -= LOCAltitudebase
	if rr.Altitude%100 != 0 {
		sb.WriteString(fmt.Sprintf("%.2fm ", alt))
	} else {
		sb.WriteString(fmt.Sprintf("%.0fm ", alt))
	}

	sb.WriteString(cmToM(rr.Size) + "m ")
	sb.WriteString(cmToM(rr.HorizPre) + "m ")
	sb.WriteString(cmToM(rr.VertPre) + "m")
	return sb.String()
}

// SIG RR. See RFC 2535. The SIG RR is identical to RRSIG and nowadays only used for SIG(0), See RFC 2931.
type SIG struct{ RRSIG }

// NewSIG0 return a new SIG with initial fields set. This can be used SIG0 transaction signing.
func NewSIG0() *SIG {
	// TODO(miek)
	return nil
}

// RRSIG RR. See RFC 4034 and RFC 3755.
type RRSIG struct {
	Hdr         Header
	TypeCovered uint16
	Algorithm   uint8
	Labels      uint8
	OrigTTL     uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	SignerName  string `dns:"domain-name"`
	Signature   string `dns:"base64"`
}

func (rr *RRSIG) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, sprintType(rr.TypeCovered),
		strconv.Itoa(int(rr.Algorithm)),
		strconv.Itoa(int(rr.Labels)),
		strconv.FormatInt(int64(rr.OrigTTL), 10),
		timeToString(rr.Expiration),
		timeToString(rr.Inception),
		strconv.Itoa(int(rr.KeyTag)),
		sprintName(rr.SignerName),
		rr.Signature)
	return sb.String()
}

// NewRRSIG returns a new RRSIG with many fields set. That can be used as a "stub" RRSIG before generating the
// signature. If incepexp, the inception and expiration are not the given, now-300s and now+2w is used.
// z is both set as the ownername and the signers name.
func NewRRSIG(z string, algorithm uint8, keytag uint16, incepexp ...uint32) *RRSIG {
	s := new(RRSIG)
	s.Hdr.Name = z
	s.Hdr.Class = ClassINET
	s.Algorithm = algorithm
	s.KeyTag = keytag
	s.SignerName = z
	if len(incepexp) == 0 {
		now := time.Now().Unix()
		s.Expiration = uint32(now - 300)
		s.Inception = uint32(now + (14 * 86400))
	} else {
		s.Expiration = incepexp[0]
		s.Inception = incepexp[1]
	}
	return s
}

// NXT RR. See RFC 2535.
type NXT struct{ NSEC }

// NSEC RR. See RFC 4034 and RFC 3755.
type NSEC struct {
	Hdr        Header
	NextDomain string   `dns:"domain-name"`
	TypeBitMap []uint16 `dns:"nsec"`
}

func (rr *NSEC) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(sprintName(rr.NextDomain))
	for _, t := range rr.TypeBitMap {
		sb.WriteByte(' ')
		sb.WriteString(sprintType(t))
	}
	return sb.String()
}

func (rr *NSEC) Len() int {
	l := rr.Hdr.Len()
	l += len(rr.NextDomain)
	l += typeBitMapLen(rr.TypeBitMap)
	return l
}

// DLV RR. See RFC 4431.
type DLV struct{ DS }

// CDS RR. See RFC 7344.
type CDS struct{ DS }

// DS RR. See RFC 4034 and RFC 3658.
type DS struct {
	Hdr        Header
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string `dns:"hex"`
}

func (rr *DS) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.KeyTag)),
		strconv.Itoa(int(rr.Algorithm)),
		strconv.Itoa(int(rr.DigestType)),
		strings.ToUpper(rr.Digest))
	return sb.String()
}

// KX RR. See RFC 2230.
type KX struct {
	Hdr        Header
	Preference uint16
	Exchanger  string `dns:"domain-name"`
}

func (rr *KX) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Preference)), sprintName(rr.Exchanger))
	return sb.String()
}

// TA RR. See http://www.watson.org/~weiler/INI1999-19.pdf.
type TA struct {
	Hdr        Header
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string `dns:"hex"`
}

func (rr *TA) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.KeyTag)),
		strconv.Itoa(int(rr.Algorithm)),
		strconv.Itoa(int(rr.DigestType)),
		strings.ToUpper(rr.Digest))
	return sb.String()
}

// TALINK RR. See https://www.iana.org/assignments/dns-parameters/TALINK/talink-completed-template.
type TALINK struct {
	Hdr          Header
	PreviousName string `dns:"domain-name"`
	NextName     string `dns:"domain-name"`
}

func (rr *TALINK) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, sprintName(rr.PreviousName), sprintName(rr.NextName))
	return sb.String()
}

// SSHFP RR. See RFC 4255.
type SSHFP struct {
	Hdr         Header
	Algorithm   uint8
	Type        uint8
	FingerPrint string `dns:"hex"`
}

func (rr *SSHFP) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Algorithm)),
		strconv.Itoa(int(rr.Type)),
		strings.ToUpper(rr.FingerPrint))
	return sb.String()
}

// KEY RR. See RFC 2535.
type KEY struct{ DNSKEY }

// CDNSKEY RR. See RFC 7344.
type CDNSKEY struct{ DNSKEY }

// DNSKEY RR. See RFC 4034 and RFC 3755.
type DNSKEY struct {
	Hdr       Header
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey string `dns:"base64"`
}

func (rr *DNSKEY) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Flags)),
		strconv.Itoa(int(rr.Protocol)),
		strconv.Itoa(int(rr.Algorithm)),
		rr.PublicKey)
	return sb.String()
}

// NewDNSKEY returns a DNSKEY with good defaults for some fields. The key's flag field is set to 256.
func NewDNSKEY(z string, algorithm uint8) *DNSKEY {
	k := new(DNSKEY)
	k.Hdr.Name = z
	k.Hdr.Class = ClassINET
	k.Algorithm = algorithm
	k.Flags = 256
	k.Protocol = 3
	return k
}

// RKEY RR. See https://www.iana.org/assignments/dns-parameters/RKEY/rkey-completed-template.
type RKEY struct {
	Hdr       Header
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey string `dns:"base64"`
}

func (rr *RKEY) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Flags)),
		strconv.Itoa(int(rr.Protocol)),
		strconv.Itoa(int(rr.Algorithm)),
		rr.PublicKey)
	return sb.String()
}

// NSAPPTR RR. See RFC 1348.
type NSAPPTR struct {
	Hdr Header
	Ptr string `dns:"domain-name"`
}

func (rr *NSAPPTR) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(sprintName(rr.Ptr))
	return sb.String()
}

// NSEC3 RR. See RFC 5155.
type NSEC3 struct {
	Hdr        Header
	Hash       uint8
	Flags      uint8
	Iterations uint16
	SaltLength uint8
	Salt       string `dns:"size-hex:SaltLength"`
	HashLength uint8
	NextDomain string   `dns:"size-base32:HashLength"`
	TypeBitMap []uint16 `dns:"nsec"`
}

func (rr *NSEC3) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Hash)),
		strconv.Itoa(int(rr.Flags)),
		strconv.Itoa(int(rr.Iterations)),
		saltToString(rr.Salt),
		rr.NextDomain)
	for _, t := range rr.TypeBitMap {
		sb.WriteByte(' ')
		sb.WriteString(sprintType(t))
	}
	return sb.String()
}

func (rr *NSEC3) Len() int {
	l := rr.Hdr.Len()
	l += 6 + len(rr.Salt)/2 + 1 + len(rr.NextDomain) + 1
	l += typeBitMapLen(rr.TypeBitMap)
	return l
}

// NSEC3PARAM RR. See RFC 5155.
type NSEC3PARAM struct {
	Hdr        Header
	Hash       uint8
	Flags      uint8
	Iterations uint16
	SaltLength uint8
	Salt       string `dns:"size-hex:SaltLength"`
}

func (rr *NSEC3PARAM) String() string {
	sb := sprintHeader(rr)
	sprintData(sb,
		strconv.Itoa(int(rr.Hash)),
		strconv.Itoa(int(rr.Flags)),
		strconv.Itoa(int(rr.Iterations)),
		saltToString(rr.Salt))
	return sb.String()
}

// TKEY RR. See RFC 2930.
type TKEY struct {
	Hdr        Header
	Algorithm  string `dns:"domain-name"`
	Inception  uint32
	Expiration uint32
	Mode       uint16
	Error      uint16
	KeySize    uint16
	Key        string `dns:"size-hex:KeySize"`
	OtherLen   uint16
	OtherData  string `dns:"size-hex:OtherLen"`
}

// TKEY has no official presentation format, but this will suffice.
func (rr *TKEY) String() string {
	sb := sprintHeader(rr)
	sprintData(sb,
		rr.Algorithm,
		timeToString(rr.Inception),
		timeToString(rr.Expiration),
		strconv.Itoa(int(rr.Mode)),
		strconv.Itoa(int(rr.Error)),
		strconv.Itoa(int(rr.KeySize)),
		rr.Key,
		strconv.Itoa(int(rr.OtherLen)),
		rr.OtherData)
	return sb.String()
}

// RFC3597 represents an unknown/generic RR. See RFC 3597.
type RFC3597 struct {
	Hdr   Header
	Rdata string `dns:"hex"`
}

func (rr *RFC3597) String() string {
	sb := strings.Builder{}

	sb.WriteString(rr.Hdr.Name)
	sb.WriteByte('\t')
	sb.WriteString(strconv.FormatInt(int64(rr.Hdr.TTL), 10))
	sb.WriteByte('\t')
	sb.WriteString("CLASS" + strconv.Itoa(int(rr.Hdr.Class)))
	sb.WriteByte('\t')
	sb.WriteString("TYPE" + strconv.Itoa(int(rr.Hdr.t)))
	sb.WriteByte('\t')

	sb.WriteByte('\\')
	sb.WriteByte('#')
	sprintData(&sb, strconv.Itoa(len(rr.Rdata)/2), rr.Rdata)
	return sb.String()
}

// URI RR. See RFC 7553.
type URI struct {
	Hdr      Header
	Priority uint16
	Weight   uint16
	Target   string `dns:"octet"` // Target is to be parsed as a sequence of character encoded octets according to RFC 3986.
}

func (rr *URI) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Priority)), strconv.Itoa(int(rr.Weight)), sprintTxtOctet(rr.Target))
	return sb.String()
}

// DHCID RR. See RFC 4701.
type DHCID struct {
	Hdr    Header
	Digest string `dns:"base64"`
}

func (rr *DHCID) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.Digest)
	return sb.String()
}

// TLSA RR. See RFC 6698.
type TLSA struct {
	Hdr          Header
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Certificate  string `dns:"hex"`
}

func (rr *TLSA) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Usage)),
		strconv.Itoa(int(rr.Selector)),
		strconv.Itoa(int(rr.MatchingType)),
		rr.Certificate)
	return sb.String()
}

// SMIMEA RR. See RFC 8162.
type SMIMEA struct {
	Hdr          Header
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Certificate  string `dns:"hex"`
}

func (rr *SMIMEA) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Usage)), strconv.Itoa(int(rr.Selector)), strconv.Itoa(int(rr.MatchingType)))

	// Every Nth char needs a space on this output. If we output
	// this as one giant line, we can't read it can in because in some cases
	// the cert length overflows scan.maxTok (2048).
	sx := splitN(rr.Certificate, 1024) // conservative value here
	sb.WriteByte(' ')
	sb.WriteString(strings.Join(sx, " "))
	return sb.String()
}

// HIP RR. See RFC 8005.
type HIP struct {
	Hdr                Header
	HitLength          uint8
	PublicKeyAlgorithm uint8
	PublicKeyLength    uint16
	Hit                string   `dns:"size-hex:HitLength"`
	PublicKey          string   `dns:"size-base64:PublicKeyLength"`
	RendezvousServers  []string `dns:"domain-name"`
}

func (rr *HIP) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.PublicKeyAlgorithm)), rr.Hit, rr.PublicKey)
	for _, d := range rr.RendezvousServers {
		sb.WriteByte(' ')
		sb.WriteString(sprintName(d))
	}
	return sb.String()
}

// NINFO RR. See https://www.iana.org/assignments/dns-parameters/NINFO/ninfo-completed-template.
type NINFO struct {
	Hdr    Header
	ZSData []string `dns:"txt"`
}

func (rr *NINFO) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(sprintTxt(rr.ZSData))
	return sb.String()
}

// NID RR. See RFC 6742.
type NID struct {
	Hdr        Header
	Preference uint16
	NodeID     uint64
}

func (rr *NID) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(strconv.Itoa(int(rr.Preference)))
	node := fmt.Sprintf("%0.16x", rr.NodeID)
	sb.WriteByte(' ')
	sb.WriteString(node[0:4])
	sb.WriteByte(':')
	sb.WriteString(node[4:8])
	sb.WriteByte(':')
	sb.WriteString(node[8:12])
	sb.WriteByte(':')
	sb.WriteString(node[12:16])
	return sb.String()
}

// L32 RR, See RFC 6742.
type L32 struct {
	Hdr        Header
	Preference uint16
	Locator32  net.IP `dns:"a"`
}

func (rr *L32) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(strconv.Itoa(int(rr.Preference)))
	if rr.Locator32 == nil {
		return sb.String()
	}
	sb.WriteByte(' ')
	sb.WriteString(rr.Locator32.String())
	return sb.String()
}

// L64 RR, See RFC 6742.
type L64 struct {
	Hdr        Header
	Preference uint16
	Locator64  uint64
}

func (rr *L64) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(strconv.Itoa(int(rr.Preference)))
	node := fmt.Sprintf("%0.16X", rr.Locator64)
	sb.WriteByte(' ')
	sb.WriteString(node[0:4])
	sb.WriteByte(':')
	sb.WriteString(node[4:8])
	sb.WriteByte(':')
	sb.WriteString(node[8:12])
	sb.WriteByte(':')
	sb.WriteString(node[12:16])
	return sb.String()
}

// LP RR. See RFC 6742.
type LP struct {
	Hdr        Header
	Preference uint16
	Fqdn       string `dns:"domain-name"`
}

func (rr *LP) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Preference)), sprintName(rr.Fqdn))
	return sb.String()
}

// EUI48 RR. See RFC 7043.
type EUI48 struct {
	Hdr     Header
	Address uint64 `dns:"uint48"`
}

func (rr *EUI48) String() string { return rr.Hdr.String() + euiToString(rr.Address, 48) }

// EUI64 RR. See RFC 7043.
type EUI64 struct {
	Hdr     Header
	Address uint64
}

func (rr *EUI64) String() string { return rr.Hdr.String() + euiToString(rr.Address, 64) }

// CAA RR. See RFC 6844.
type CAA struct {
	Hdr   Header
	Flag  uint8
	Tag   string
	Value string `dns:"octet"` // Value is the character-string encoding of the value field as specified in RFC 1035, Section 5.1.
}

func (rr *CAA) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Flag)), rr.Tag, sprintTxtOctet(rr.Value))
	return sb.String()
}

// UID RR. Deprecated, IANA-Reserved.
type UID struct {
	Hdr Header
	Uid uint32
}

func (rr *UID) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(strconv.FormatInt(int64(rr.Uid), 10))
	return sb.String()
}

// GID RR. Deprecated, IANA-Reserved.
type GID struct {
	Hdr Header
	Gid uint32
}

func (rr *GID) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(strconv.FormatInt(int64(rr.Gid), 10))
	return sb.String()
}

// UINFO RR. Deprecated, IANA-Reserved.
type UINFO struct {
	Hdr   Header
	Uinfo string
}

func (rr *UINFO) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(sprintTxt([]string{rr.Uinfo}))
	return sb.String()
}

// EID RR. See http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt.
type EID struct {
	Hdr      Header
	Endpoint string `dns:"hex"`
}

func (rr *EID) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(strings.ToUpper(rr.Endpoint))
	return sb.String()
}

// NIMLOC RR. See http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt.
type NIMLOC struct {
	Hdr     Header
	Locator string `dns:"hex"`
}

func (rr *NIMLOC) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.Locator)
	return sb.String()
}

// OPENPGPKEY RR. See RFC 7929.
type OPENPGPKEY struct {
	Hdr       Header
	PublicKey string `dns:"base64"`
}

func (rr *OPENPGPKEY) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.PublicKey)
	return sb.String()
}

// CSYNC RR. See RFC 7477.
type CSYNC struct {
	Hdr        Header
	Serial     uint32
	Flags      uint16
	TypeBitMap []uint16 `dns:"nsec"`
}

func (rr *CSYNC) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.FormatInt(int64(rr.Serial), 10), strconv.Itoa(int(rr.Flags)))
	for _, t := range rr.TypeBitMap {
		sb.WriteByte(' ')
		sb.WriteString(sprintType(t))
	}
	return sb.String()
}

func (rr *CSYNC) Len() int {
	l := rr.Hdr.Len()
	l += 4 + 2
	l += typeBitMapLen(rr.TypeBitMap)
	return l
}

// ZONEMD RR, RFC 8976.
type ZONEMD struct {
	Hdr    Header
	Serial uint32
	Scheme uint8
	Hash   uint8
	Digest string `dns:"hex"`
}

func (rr *ZONEMD) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Serial)), strconv.Itoa(int(rr.Scheme)), strconv.Itoa(int(rr.Hash)), rr.Digest)
	return sb.String()
}

// OPT is the EDNS0 RR appended to messages to convey extra (meta) information. See RFC 6891. This record is
// not (directly) found in messages as the pack and unpack function take care of this. Any EDNS0 options are
// found in the [Pseudo] section of the message. There should be rarely the need to access specifics of this
// RR as you can just set things directly on [Msg].
type OPT struct {
	Hdr     Header
	Options []EDNS0 `dns:"opt"`
}

// See opt.go for other methods.

func (rr *OPT) String() string { return "" }

func (rr *OPT) Len() int {
	l := rr.Hdr.Len()
	for i := range rr.Options {
		l += rr.Options[i].Len()
	}
	return l
}

var _ RR = &OPT{}

// RESINFO RR. See RFC 9606.
type RESINFO struct {
	Hdr Header
	Txt []string `dns:"txt"`
}

func (rr *RESINFO) String() string { return rr.Hdr.String() + sprintTxt(rr.Txt) }

// SVCB RR. See RFC 9460.
type SVCB struct {
	Hdr      Header
	Priority uint16      // If zero, Value must be empty or discarded by the user of this library.
	Target   string      `dns:"domain-name"`
	Value    []svcb.Pair `dns:"pairs"`
}

func (rr *SVCB) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Priority)), sprintName(rr.Target))
	for _, p := range rr.Value {
		sb.WriteByte(' ')
		k := svcb.PairToKey(p)
		sb.WriteString(svcb.KeyToString(k))
		sb.WriteByte('=')
		sb.WriteByte('"')
		sb.WriteString(p.String())
		sb.WriteByte('"')
	}
	return sb.String()
}

// HTTPS RR. See RFC 9460. Everything valid for SVCB applies to HTTPS as well.
// Except that the HTTPS record is intended for use with the HTTP and HTTPS protocols.
type HTTPS struct{ SVCB }

func (rr *HTTPS) String() string { return rr.SVCB.String() }

// DELEG RR. See RFC ... (draft ...)
type DELEG struct {
	Hdr   Header
	Value []deleg.Info `dns:"infos"`
}

func (rr *DELEG) String() string {
	sb := sprintHeader(rr)
	for _, i := range rr.Value {
		sb.WriteByte(' ')
		k := deleg.InfoToKey(i)
		sb.WriteString(svcb.KeyToString(k))
		sb.WriteByte('=')
		sb.WriteByte('"')
		sb.WriteString(i.String())
		sb.WriteByte('"')
	}
	return sb.String()
}

type DELEGI struct{ DELEG }

func (rr *DELEGI) String() string { return rr.DELEG.String() }

// Meta RRs

// ANY is a wildcard record. See RFC 1035, Section 3.2.3. ANY is named "*" there.
type ANY struct {
	Hdr Header
}

func (rr *ANY) String() string { return rr.Hdr.String() }

func (*ANY) parse(c *zlexer, origin string) *ParseError {
	return &ParseError{err: "ANY records do not have a presentation format"}
}

// AXFR is a meta record used (solely) in question sections to ask for a zone transfer.
type AXFR struct {
	Hdr Header
}

func (rr *AXFR) String() string { return rr.Hdr.String() }

func (*AXFR) parse(c *zlexer, origin string) *ParseError {
	return &ParseError{err: "AXFR records do not have a presentation format"}
}

// IXFR is a meta record used (solely) in question sections to ask for an incremental zone transfer.
type IXFR struct {
	Hdr Header
}

func (rr *IXFR) String() string { return rr.Hdr.String() }

func (*IXFR) parse(c *zlexer, origin string) *ParseError {
	return &ParseError{err: "IXFR records do not have a presentation format"}
}

// TSIG is the RR the holds the transaction signature of a message. See RFC 2845 and RFC 4635.
// A TSIG RR when created must have the [ClassANY], algorithm, timesigned, and optianal fudge factor.
// The owner name is the name of the key. I.e:
//
//	tsig := &dns.TSIG{Hdr: dns.Header{Name: "keyname.", Class: dns.ClassANY}, Algorithm: dns.HmacSHA512,
//			TimeSigned: uint64(time.Now().Unix())}
//
// See [NewTSIG] for an easier way of doing this.
type TSIG struct {
	Hdr        Header
	Algorithm  string `dns:"domain-name"` // Algorithm is encoded as a name, see HmacSHAXXX contstants.
	TimeSigned uint64 `dns:"uint48"`
	Fudge      uint16
	MACSize    uint16
	MAC        string `dns:"size-hex:MACSize"`
	OrigID     uint16 // OrigID is the original message ID, when creating a TSIG this should be set to the message ID.
	Error      uint16
	OtherLen   uint16
	OtherData  string `dns:"size-hex:OtherLen"`
}

func (rr *TSIG) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, rr.Algorithm, tsigTimeToString(rr.TimeSigned),
		strconv.Itoa(int(rr.Fudge)), strconv.Itoa(int(rr.MACSize)),
		strings.ToUpper(rr.MAC), strconv.Itoa(int(rr.OrigID)),
		strconv.Itoa(int(rr.Error)), strconv.Itoa(int(rr.OtherLen)), rr.OtherData)
	return sb.String()
}

// NewTSIG return a new TSIG with initial fields set. If fudge is zero, the default of 300 is used.
// If timesigned isn't given the current time is used via time.Now().Unix().
func NewTSIG(z, algorithm string, fudge uint16, timesigned ...int64) *TSIG {
	t := new(TSIG)
	t.Hdr.Name = z
	t.Hdr.Class = ClassANY
	t.Algorithm = algorithm
	if fudge == 0 {
		fudge = 300
	}
	t.Fudge = fudge
	if len(timesigned) == 0 {
		t.TimeSigned = uint64(time.Now().Unix())
	} else {
		t.TimeSigned = uint64(timesigned[0])
	}
	return t
}

func (*TSIG) parse(c *zlexer, origin string) *ParseError {
	return &ParseError{err: "TSIG records do not have a presentation format"}
}
