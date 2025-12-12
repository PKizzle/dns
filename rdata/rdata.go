package rdata

import (
	"net/netip"

	"codeberg.org/miekg/dns/deleg"
	"codeberg.org/miekg/dns/svcb"
)

// NULL RR. See RFC 1035.
type NULL struct {
	Null string `dns:"any"`
}

// CNAME RR. See RFC 1034.
type CNAME struct {
	Target string `dns:"cdomain-name"`
}

// HINFO RR. See RFC 1034.
type HINFO struct {
	Cpu string
	Os  string
}

// MB RR. See RFC 1035.
type MB struct {
	Mb string `dns:"cdomain-name"`
}

// MG RR. See RFC 1035.
type MG struct {
	Mg string `dns:"cdomain-name"`
}

// MINFO RR. See RFC 1035.
type MINFO struct {
	Rmail string `dns:"cdomain-name"`
	Email string `dns:"cdomain-name"`
}

// MR RR. See RFC 1035.
type MR struct {
	Mr string `dns:"cdomain-name"`
}

// MF RR. See RFC 1035.
type MF struct {
	Mf string `dns:"cdomain-name"`
}

// MD RR. See RFC 1035.
type MD struct {
	Md string `dns:"cdomain-name"`
}

// MX RR. See RFC 1035.
type MX struct {
	Preference uint16
	Mx         string `dns:"cdomain-name"`
}

// AFSDB RR. See RFC 1183.
type AFSDB struct {
	Subtype  uint16
	Hostname string `dns:"domain-name"`
}

// X25 RR. See RFC 1183, Section 3.1.
type X25 struct {
	PSDNAddress string
}

// ISDN RR. See RFC 1183, Section 3.2.
type ISDN struct {
	Address    string
	SubAddress string
}

// RT RR. See RFC 1183, Section 3.3.
type RT struct {
	Preference uint16
	Host       string `dns:"domain-name"` // RFC 3597 prohibits compressing records not defined in RFC 1035.
}

// NS RR. See RFC 1035.
type NS struct {
	Ns string `dns:"cdomain-name"`
}

// PTR RR. See RFC 1035.
type PTR struct {
	Ptr string `dns:"cdomain-name"`
}

// RP RR. See RFC 1138, Section 2.2.
type RP struct {
	Mbox string `dns:"domain-name"`
	Txt  string `dns:"domain-name"`
}

// SOA RR. See RFC 1035.
type SOA struct {
	Ns      string `dns:"cdomain-name"`
	Mbox    string `dns:"cdomain-name"`
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minttl  uint32
}

// TXT RR. See RFC 1035.
type TXT struct {
	Txt []string `dns:"txt"`
}

// IPN RR. See https://www.iana.org/assignments/dns-parameters/IPN/ipn-completed-template.
type IPN struct {
	Node uint64
}

// SRV RR. See RFC 2782.
type SRV struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string `dns:"domain-name"`
}

// NAPTR RR. See RFC 2915.
type NAPTR struct {
	Order       uint16
	Preference  uint16
	Flags       string
	Service     string
	Regexp      string
	Replacement string `dns:"domain-name"`
}

// CERT RR. See RFC 4398.
type CERT struct {
	Type        uint16
	KeyTag      uint16
	Algorithm   uint8
	Certificate string `dns:"base64"`
}

// DNAME RR. See RFC 2672.
type DNAME struct {
	Target string `dns:"domain-name"`
}

// A RR. See RFC 1035.
type A struct {
	Addr netip.Addr `dns:"a"`
}

// AAAA RR. See RFC 3596.
type AAAA struct {
	Addr netip.Addr `dns:"aaaa"`
}

// PX RR. See RFC 2163.
type PX struct {
	Preference uint16
	Map822     string `dns:"domain-name"`
	Mapx400    string `dns:"domain-name"`
}

// GPOS RR. See RFC 1712.
type GPOS struct {
	Longitude string
	Latitude  string
	Altitude  string
}

// LOC RR. See RFC 1876.
type LOC struct {
	Version   uint8
	Size      uint8
	HorizPre  uint8
	VertPre   uint8
	Latitude  uint32
	Longitude uint32
	Altitude  uint32
}

// RRSIG RR. See RFC 4034 and RFC 3755.
type RRSIG struct {
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

// NSEC RR. See RFC 4034 and RFC 3755.
type NSEC struct {
	NextDomain string   `dns:"domain-name"`
	TypeBitMap []uint16 `dns:"nsec"`
}

// DS RR. See RFC 4034 and RFC 3658.
type DS struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string `dns:"hex"`
}

// KX RR. See RFC 2230.
type KX struct {
	Preference uint16
	Exchanger  string `dns:"domain-name"`
}

// TA RR. See http://www.watson.org/~weiler/INI1999-19.pdf.
type TA struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string `dns:"hex"`
}

// TALINK RR. See https://www.iana.org/assignments/dns-parameters/TALINK/talink-completed-template.
type TALINK struct {
	PreviousName string `dns:"domain-name"`
	NextName     string `dns:"domain-name"`
}

// SSHFP RR. See RFC 4255.
type SSHFP struct {
	Algorithm   uint8
	Type        uint8
	FingerPrint string `dns:"hex"`
}

// DNSKEY RR. See RFC 4034 and RFC 3755.
type DNSKEY struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey string `dns:"base64"`
}

// RKEY RR. See https://www.iana.org/assignments/dns-parameters/RKEY/rkey-completed-template.
type RKEY struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey string `dns:"base64"`
}

// NSAPPTR RR. See RFC 1348.
type NSAPPTR struct {
	Ptr string `dns:"domain-name"`
}

// NSEC3 RR. See RFC 5155.
type NSEC3 struct {
	Hash       uint8
	Flags      uint8
	Iterations uint16
	SaltLength uint8
	Salt       string `dns:"size-hex:SaltLength"`
	HashLength uint8
	NextDomain string   `dns:"size-base32:HashLength"`
	TypeBitMap []uint16 `dns:"nsec"`
}

// NSEC3PARAM RR. See RFC 5155.
type NSEC3PARAM struct {
	Hash       uint8
	Flags      uint8
	Iterations uint16
	SaltLength uint8
	Salt       string `dns:"size-hex:SaltLength"`
}

// TKEY RR. See RFC 2930.
type TKEY struct {
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

// RFC3597 represents an unknown/generic RR. See RFC 3597.
type RFC3597 struct {
	RRType uint16 `dns:"-"` // actual type
	Data   string `dns:"hex"`
}

// URI RR. See RFC 7553.
type URI struct {
	Priority uint16
	Weight   uint16
	Target   string `dns:"any"` // Target is to be parsed as a sequence of character encoded octets according to RFC 3986.
}

// DHCID RR. See RFC 4701.
type DHCID struct {
	Digest string `dns:"base64"`
}

// TLSA RR. See RFC 6698.
type TLSA struct {
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Certificate  string `dns:"hex"`
}

// SMIMEA RR. See RFC 8162.
type SMIMEA struct {
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Certificate  string `dns:"hex"`
}

// HIP RR. See RFC 8005.
type HIP struct {
	HitLength          uint8
	PublicKeyAlgorithm uint8
	PublicKeyLength    uint16
	Hit                string   `dns:"size-hex:HitLength"`
	PublicKey          string   `dns:"size-base64:PublicKeyLength"`
	RendezvousServers  []string `dns:"domain-name"`
}

// NINFO RR. See https://www.iana.org/assignments/dns-parameters/NINFO/ninfo-completed-template.
type NINFO struct {
	ZSData []string `dns:"txt"`
}

// NID RR. See RFC 6742.
type NID struct {
	Preference uint16
	NodeID     uint64
}

// L32 RR, See RFC 6742.
type L32 struct {
	Preference uint16
	Locator32  netip.Addr `dns:"a"`
}

// L64 RR, See RFC 6742.
type L64 struct {
	Preference uint16
	Locator64  uint64
}

// LP RR. See RFC 6742.
type LP struct {
	Preference uint16
	Fqdn       string `dns:"domain-name"`
}

type EUI48 struct {
	Address uint64 `dns:"uint48"`
}

// EUI64 RR. See RFC 7043.
type EUI64 struct {
	Address uint64
}

// CAA RR. See RFC 6844.
type CAA struct {
	Flag  uint8
	Tag   string
	Value string `dns:"any"` // Value is the character-string encoding of the value field as specified in RFC 1035, Section 5.1.
}

// UID RR. Deprecated, IANA-Reserved.
type UID struct {
	Uid uint32
}

// GID RR. Deprecated, IANA-Reserved.
type GID struct {
	Gid uint32
}

// UINFO RR. Deprecated, IANA-Reserved.
type UINFO struct {
	Uinfo string
}

// EID RR. See http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt.
type EID struct {
	Endpoint string `dns:"hex"`
}

// NIMLOC RR. See http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt.
type NIMLOC struct {
	Locator string `dns:"hex"`
}

// OPENPGPKEY RR. See RFC 7929.
type OPENPGPKEY struct {
	PublicKey string `dns:"base64"`
}

// CSYNC RR. See RFC 7477.
type CSYNC struct {
	Serial     uint32
	Flags      uint16
	TypeBitMap []uint16 `dns:"nsec"`
}

// ZONEMD RR, RFC 8976.
type ZONEMD struct {
	Serial uint32
	Scheme uint8
	Hash   uint8
	Digest string `dns:"hex"`
}

// SVCB RR. See RFC 9460.
type SVCB struct {
	Priority uint16      // If zero, Value must be empty or discarded by the user of this library.
	Target   string      `dns:"domain-name"`
	Value    []svcb.Pair `dns:"pairs"`
}

// DELEG RR. See draft https://datatracker.ietf.org/doc/draft-ietf-deleg/.
type DELEG struct {
	Value []deleg.Info `dns:"infos"`
}

// See RFC 9859.
type DSYNC struct {
	Type   uint16
	Scheme uint8
	Port   uint16
	Target string `dns:"domain-name"`
}

// TSIG RR.
type TSIG struct {
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
