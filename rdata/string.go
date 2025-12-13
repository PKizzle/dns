package rdata

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns/deleg"
	"codeberg.org/miekg/dns/internal/dnsstring"
	"codeberg.org/miekg/dns/pool"
	"codeberg.org/miekg/dns/svcb"
)

var builderPool = &pool.Builder{Pool: sync.Pool{New: func() any { return strings.Builder{} }}}

func (rr RRSIG) String() string {
	sb := builderPool.Get()
	sprintData(&sb, typeToString(rr.TypeCovered),
		strconv.Itoa(int(rr.Algorithm)),
		strconv.Itoa(int(rr.Labels)),
		strconv.FormatInt(int64(rr.OrigTTL), 10),
		dnsutilTimeToString(rr.Expiration),
		dnsutilTimeToString(rr.Inception),
		strconv.Itoa(int(rr.KeyTag)),
		rr.SignerName,
		rr.Signature)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr LOC) String() string {
	sb := builderPool.Get()
	lat := rr.Latitude
	ns := "N"
	if lat > dnsstring.LOCEquator {
		lat = lat - dnsstring.LOCEquator
	} else {
		ns = "S"
		lat = dnsstring.LOCEquator - lat
	}
	h := lat / dnsstring.LOCDegrees
	lat = lat % dnsstring.LOCDegrees
	m := lat / dnsstring.LOCHours
	lat = lat % dnsstring.LOCHours

	sb.WriteString(fmt.Sprintf("%02d %02d %0.3f %s ", h, m, float64(lat)/1000, ns))

	lon := rr.Longitude
	ew := "E"
	if lon > dnsstring.LOCPrimemeridian {
		lon = lon - dnsstring.LOCPrimemeridian
	} else {
		ew = "W"
		lon = dnsstring.LOCPrimemeridian - lon
	}
	h = lon / dnsstring.LOCDegrees
	lon = lon % dnsstring.LOCDegrees
	m = lon / dnsstring.LOCHours
	lon = lon % dnsstring.LOCHours

	sb.WriteString(fmt.Sprintf("%02d %02d %0.3f %s ", h, m, float64(lon)/1000, ew))

	alt := float64(rr.Altitude) / 100
	alt -= dnsstring.LOCAltitudebase
	if rr.Altitude%100 != 0 {
		sb.WriteString(fmt.Sprintf("%.2fm ", alt))
	} else {
		sb.WriteString(fmt.Sprintf("%.0fm ", alt))
	}

	sb.WriteString(cmToM(rr.Size) + "m ")
	sb.WriteString(cmToM(rr.HorizPre) + "m ")
	sb.WriteString(cmToM(rr.VertPre) + "m")
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr CERT) String() string {
	sb := builderPool.Get()
	if certtype, ok := dnsstring.CertTypeToString[rr.Type]; !ok {
		sb.WriteString(strconv.Itoa(int(rr.Type)))
	} else {
		sb.WriteString(certtype)
	}

	sb.WriteByte(' ')
	sb.WriteString(strconv.Itoa(int(rr.KeyTag)))
	sb.WriteByte(' ')

	if algorithm, ok := dnsstring.AlgorithmToString[rr.Algorithm]; ok {
		sb.WriteString(algorithm)
	} else {
		sb.WriteString(strconv.Itoa(int(rr.Algorithm)))
	}
	sb.WriteByte(' ')

	sb.WriteString(rr.Certificate)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *NSEC3) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.Hash)),
		strconv.Itoa(int(rr.Flags)),
		strconv.Itoa(int(rr.Iterations)),
		saltToString(rr.Salt),
		rr.NextDomain)
	for _, t := range rr.TypeBitMap {
		sb.WriteByte(' ')
		sb.WriteString(typeToString(t))
	}
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *NSEC3PARAM) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.Hash)),
		strconv.Itoa(int(rr.Flags)),
		strconv.Itoa(int(rr.Iterations)),
		saltToString(rr.Salt))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr NULL) String() string  { return rr.Null }
func (rr CNAME) String() string { return rr.Target }
func (rr HINFO) String() string { return sprintTxt([]string{rr.Cpu, rr.Os}) }
func (rr MB) String() string    { return rr.Mb }
func (rr MG) String() string    { return rr.Mg }
func (rr MR) String() string    { return rr.Mr }
func (rr MF) String() string    { return rr.Mf }
func (rr MD) String() string    { return rr.Md }
func (rr X25) String() string   { return rr.PSDNAddress }
func (rr *NS) String() string   { return rr.Ns }

func (rr MINFO) String() string {
	sb := builderPool.Get()
	sprintData(&sb, rr.Rmail, rr.Email)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr MX) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.Preference)), rr.Mx)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *AFSDB) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.Subtype)), rr.Hostname)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *ISDN) String() string {
	sb := builderPool.Get()
	sb.WriteString(sprintTxt([]string{rr.Address, rr.SubAddress}))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *RT) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.Preference)), rr.Host)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *PTR) String() string { return rr.Ptr }

func (rr *RP) String() string {
	sb := builderPool.Get()
	sprintData(&sb, rr.Mbox, rr.Txt)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *SOA) String() string {
	sb := builderPool.Get()
	sprintData(&sb, rr.Ns, rr.Mbox,
		strconv.FormatInt(int64(rr.Serial), 10),
		strconv.FormatInt(int64(rr.Refresh), 10),
		strconv.FormatInt(int64(rr.Retry), 10),
		strconv.FormatInt(int64(rr.Expire), 10),
		strconv.FormatInt(int64(rr.Minttl), 10))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *TXT) String() string {
	sb := builderPool.Get()
	sb.WriteString(sprintTxt(rr.Txt))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *IPN) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.Node)))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *SRV) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.Priority)),
		strconv.Itoa(int(rr.Weight)),
		strconv.Itoa(int(rr.Port)), rr.Target)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *NAPTR) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.Order)), strconv.Itoa(int(rr.Preference)))

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
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *DNAME) String() string { return rr.Target }

func (rr *A) String() string {
	sb := builderPool.Get()
	defer builderPool.Put(sb)
	if !rr.Addr.IsValid() {
		return sb.String()
	}
	sb.WriteString(rr.Addr.String())
	return sb.String()
}

func (rr *AAAA) String() string {
	sb := builderPool.Get()
	defer builderPool.Put(sb)
	if !rr.Addr.IsValid() {
		return sb.String()
	}

	sb.WriteString(rr.Addr.String())
	return sb.String()
}

func (rr *PX) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.Preference)), rr.Map822, rr.Mapx400)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *GPOS) String() string {
	sb := builderPool.Get()
	sprintData(&sb, rr.Longitude, rr.Latitude, rr.Altitude)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *NSEC) String() string {
	sb := builderPool.Get()
	sb.WriteString(rr.NextDomain)
	for _, t := range rr.TypeBitMap {
		sb.WriteByte(' ')
		sb.WriteString(typeToString(t))
	}
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *DS) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.KeyTag)),
		strconv.Itoa(int(rr.Algorithm)),
		strconv.Itoa(int(rr.DigestType)),
		strings.ToUpper(rr.Digest))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *KX) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.Preference)), rr.Exchanger)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *TA) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.KeyTag)),
		strconv.Itoa(int(rr.Algorithm)),
		strconv.Itoa(int(rr.DigestType)),
		strings.ToUpper(rr.Digest))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

// TALINK RR. See https://www.iana.org/assignments/dns-parameters/TALINK/talink-completed-template.
type TALINK struct {
	Hdr Header
	rdata.TALINK
}

func (rr *TALINK) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, rr.PreviousName, rr.NextName)
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// SSHFP RR. See RFC 4255.
type SSHFP struct {
	Hdr Header
	rdata.SSHFP
}

func (rr *SSHFP) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Algorithm)),
		strconv.Itoa(int(rr.Type)),
		strings.ToUpper(rr.FingerPrint))
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// KEY RR. See RFC 2535.
type KEY struct{ DNSKEY }

func (rr *KEY) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Flags)),
		strconv.Itoa(int(rr.Protocol)),
		strconv.Itoa(int(rr.Algorithm)),
		rr.PublicKey)
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// CDNSKEY RR. See RFC 7344.
type CDNSKEY struct{ DNSKEY }

func (rr *CDNSKEY) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Flags)),
		strconv.Itoa(int(rr.Protocol)),
		strconv.Itoa(int(rr.Algorithm)),
		rr.PublicKey)
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// DNSKEY RR. See RFC 4034 and RFC 3755.
type DNSKEY struct {
	Hdr Header
	rdata.DNSKEY
}

func (rr *DNSKEY) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Flags)),
		strconv.Itoa(int(rr.Protocol)),
		strconv.Itoa(int(rr.Algorithm)),
		rr.PublicKey)
	s := sb.String()
	builderPool.Put(*sb)
	return s
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
	Hdr Header
	rdata.RKEY
}

func (rr *RKEY) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Flags)),
		strconv.Itoa(int(rr.Protocol)),
		strconv.Itoa(int(rr.Algorithm)),
		rr.PublicKey)
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// NSAPPTR RR. See RFC 1348.
type NSAPPTR struct {
	Hdr Header
	rdata.NSAPPTR
}

func (rr *NSAPPTR) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.Ptr)
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// NSEC3 RR. See RFC 5155.
type NSEC3 struct {
	Hdr Header
	rdata.NSEC3
}

func (rr *NSEC3) String() string {
	sb := sprintHeader(rr)
	defer builderPool.Put(*sb)
	sb.WriteString(rr.NSEC3.String())
	return sb.String()
}

func (rr *NSEC3) Len() int { return rr.Hdr.Len() + rr.NSEC3.Len() }

// NSEC3PARAM RR. See RFC 5155.
type NSEC3PARAM struct {
	Hdr Header
	rdata.NSEC3PARAM
}

func (rr *NSEC3PARAM) String() string {
	sb := sprintHeader(rr)
	defer builderPool.Put(*sb)
	sb.WriteString(rr.NSEC3PARAM.String())
	return sb.String()
}

// TKEY RR. See RFC 2930.
type TKEY struct {
	Hdr Header
	rdata.TKEY
}

// TKEY has no official presentation format, but this will suffice.
func (rr *TKEY) String() string {
	sb := sprintHeader(rr)
	sprintData(sb,
		rr.Algorithm,
		dnsutilTimeToString(rr.Inception),
		dnsutilTimeToString(rr.Expiration),
		strconv.Itoa(int(rr.Mode)),
		strconv.Itoa(int(rr.Error)),
		strconv.Itoa(int(rr.KeySize)),
		rr.Key,
		strconv.Itoa(int(rr.OtherLen)),
		rr.OtherData)
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// RFC3597 represents an unknown/generic RR. See RFC 3597.
type RFC3597 struct {
	Hdr Header
	rdata.RFC3597
}

func (rr *RFC3597) String() string {
	sb := strings.Builder{}

	sb.WriteString(rr.Hdr.Name)
	sb.WriteByte('\t')
	sb.WriteString(strconv.FormatInt(int64(rr.Hdr.TTL), 10))
	sb.WriteByte('\t')
	sb.WriteString("CLASS" + strconv.Itoa(int(rr.Hdr.Class)))
	sb.WriteByte('\t')
	sb.WriteString("TYPE" + strconv.Itoa(int(rr.RRType)))
	sb.WriteByte('\t')

	sb.WriteByte('\\')
	sb.WriteByte('#')
	sprintData(&sb, strconv.Itoa(len(rr.Data)/2), rr.Data)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

// Type implements the Typer interface.
func (rr *RFC3597) Type() uint16 { return rr.RRType }

// URI RR. See RFC 7553.
type URI struct {
	Hdr Header
	rdata.URI
}

func (rr *URI) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Priority)), strconv.Itoa(int(rr.Weight)), sprintTxt([]string{rr.Target}))
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// DHCID RR. See RFC 4701.
type DHCID struct {
	Hdr Header
	rdata.DHCID
}

func (rr *DHCID) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.Digest)
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// TLSA RR. See RFC 6698.
type TLSA struct {
	Hdr Header
	rdata.TLSA
}

func (rr *TLSA) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Usage)),
		strconv.Itoa(int(rr.Selector)),
		strconv.Itoa(int(rr.MatchingType)),
		rr.Certificate)
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// SMIMEA RR. See RFC 8162.
type SMIMEA struct {
	Hdr Header
	rdata.SMIMEA
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
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// HIP RR. See RFC 8005.
type HIP struct {
	Hdr Header
	rdata.HIP
}

func (rr *HIP) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.PublicKeyAlgorithm)), rr.Hit, rr.PublicKey)
	for _, d := range rr.RendezvousServers {
		sb.WriteByte(' ')
		sb.WriteString(d)
	}
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// NINFO RR. See https://www.iana.org/assignments/dns-parameters/NINFO/ninfo-completed-template.
type NINFO struct {
	Hdr Header
	rdata.NINFO
}

func (rr *NINFO) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(sprintTxt(rr.ZSData))
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// NID RR. See RFC 6742.
type NID struct {
	Hdr Header
	rdata.NID
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
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// L32 RR, See RFC 6742.
type L32 struct {
	Hdr Header
	rdata.L32
}

func (rr *L32) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(strconv.Itoa(int(rr.Preference)))
	if !rr.Locator32.IsValid() {
		s := sb.String()
		builderPool.Put(*sb)
		return s
	}
	sb.WriteByte(' ')
	sb.WriteString(rr.Locator32.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// L64 RR, See RFC 6742.
type L64 struct {
	Hdr Header
	rdata.L64
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
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// LP RR. See RFC 6742.
type LP struct {
	Hdr Header
	rdata.LP
}

func (rr *LP) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Preference)), rr.Fqdn)
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// EUI48 RR. See RFC 7043.
type EUI48 struct {
	Hdr Header
	rdata.EUI48
}

func (rr *EUI48) String() string { return rr.Hdr.String() + euiToString(rr.Address, 48) }

// EUI64 RR. See RFC 7043.
type EUI64 struct {
	Hdr Header
	rdata.EUI64
}

func (rr *EUI64) String() string { return rr.Hdr.String() + euiToString(rr.Address, 64) }

// CAA RR. See RFC 6844.
type CAA struct {
	Hdr Header
	rdata.CAA
}

func (rr *CAA) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Flag)), rr.Tag, sprintTxt([]string{rr.Value}))
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// UID RR. Deprecated, IANA-Reserved.
type UID struct {
	Hdr Header
	rdata.UID
}

func (rr *UID) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(strconv.FormatInt(int64(rr.Uid), 10))
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// GID RR. Deprecated, IANA-Reserved.
type GID struct {
	Hdr Header
	rdata.GID
}

func (rr *GID) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(strconv.FormatInt(int64(rr.Gid), 10))
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// UINFO RR. Deprecated, IANA-Reserved.
type UINFO struct {
	Hdr Header
	rdata.UINFO
}

func (rr *UINFO) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(sprintTxt([]string{rr.Uinfo}))
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// EID RR. See http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt.
type EID struct {
	Hdr Header
	rdata.EID
}

func (rr *EID) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(strings.ToUpper(rr.Endpoint))
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// NIMLOC RR. See http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt.
type NIMLOC struct {
	Hdr Header
	rdata.NIMLOC
}

func (rr *NIMLOC) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.Locator)
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// OPENPGPKEY RR. See RFC 7929.
type OPENPGPKEY struct {
	Hdr Header
	rdata.OPENPGPKEY
}

func (rr *OPENPGPKEY) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.PublicKey)
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// CSYNC RR. See RFC 7477.
type CSYNC struct {
	Hdr Header
	rdata.CSYNC
}

func (rr *CSYNC) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.FormatInt(int64(rr.Serial), 10), strconv.Itoa(int(rr.Flags)))
	for _, t := range rr.TypeBitMap {
		sb.WriteByte(' ')
		sb.WriteString(typeToString(t))
	}
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

func (rr *CSYNC) Len() int { return rr.Hdr.Len() + rr.CSYNC.Len() }

// ZONEMD RR, RFC 8976.
type ZONEMD struct {
	Hdr Header
	rdata.ZONEMD
}

func (rr *ZONEMD) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Serial)), strconv.Itoa(int(rr.Scheme)), strconv.Itoa(int(rr.Hash)), rr.Digest)
	s := sb.String()
	builderPool.Put(*sb)
	return s
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
type RESINFO struct{ TXT }

func (rr *RESINFO) String() string { return rr.Hdr.String() + sprintTxt(rr.Txt) }

// SVCB RR. See RFC 9460.
type SVCB struct {
	Hdr Header
	rdata.SVCB
}

func (rr *SVCB) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Priority)), rr.Target)
	for _, p := range rr.Value {
		sb.WriteByte(' ')
		k := svcb.PairToKey(p)
		sb.WriteString(svcb.KeyToString(k))
		sb.WriteByte('=')
		sb.WriteByte('"')
		sb.WriteString(p.String())
		sb.WriteByte('"')
	}
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// HTTPS RR. See RFC 9460. Everything valid for SVCB applies to HTTPS as well.
// Except that the HTTPS record is intended for use with the HTTP and HTTPS protocols.
type HTTPS struct{ SVCB }

func (rr *HTTPS) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, strconv.Itoa(int(rr.Priority)), rr.Target)
	for _, p := range rr.Value {
		sb.WriteByte(' ')
		k := svcb.PairToKey(p)
		sb.WriteString(svcb.KeyToString(k))
		sb.WriteByte('=')
		sb.WriteByte('"')
		sb.WriteString(p.String())
		sb.WriteByte('"')
	}
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// DELEG RR. See draft https://datatracker.ietf.org/doc/draft-ietf-deleg/.
type DELEG struct {
	Hdr Header
	rdata.DELEG
}

func (rr *DELEG) String() string {
	sb := sprintHeader(rr)
	for _, i := range rr.Value {
		sb.WriteByte(' ')
		k := deleg.InfoToKey(i)
		sb.WriteString(deleg.KeyToString(k))
		sb.WriteByte('=')
		sb.WriteByte('"')
		sb.WriteString(i.String())
		sb.WriteByte('"')
	}
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

type DELEGI struct{ DELEG }

func (rr *DELEGI) String() string {
	sb := sprintHeader(rr)
	for _, i := range rr.Value {
		sb.WriteByte(' ')
		k := deleg.InfoToKey(i)
		sb.WriteString(deleg.KeyToString(k))
		sb.WriteByte('=')
		sb.WriteByte('"')
		sb.WriteString(i.String())
		sb.WriteByte('"')
	}
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// See RFC 9859
type DSYNC struct {
	Hdr Header
	rdata.DSYNC
}

func (rr *DSYNC) String() string {
	sb := sprintHeader(rr)

	sb.WriteString(TypeToString[rr.Type])
	sb.WriteByte(' ')
	if rr.Scheme == 1 {
		sb.WriteString("NOTIFY")
	} else {
		sb.WriteString(strconv.Itoa(int(rr.Scheme)))
	}
	sb.WriteByte(' ')

	sb.WriteString(strconv.Itoa(int(rr.Port)))
	sb.WriteByte(' ')
	sb.WriteString(rr.Target)

	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// Meta RRs

// ANY is a wildcard record. See RFC 1035, Section 3.2.3. ANY is named "*" there.
type ANY struct {
	Hdr Header
}

func (rr *ANY) Len() int       { return rr.Hdr.Len() }
func (rr *ANY) String() string { return rr.Hdr.String() }

func (*ANY) parse(c *zlexer, origin string) *ParseError {
	return &ParseError{err: "ANY records do not have a presentation format"}
}

// AXFR is a meta record used (solely) in question sections to ask for a zone transfer.
type AXFR struct {
	Hdr Header
}

func (rr *AXFR) Len() int       { return rr.Hdr.Len() }
func (rr *AXFR) String() string { return rr.Hdr.String() }

func (*AXFR) parse(c *zlexer, origin string) *ParseError {
	return &ParseError{err: "AXFR records do not have a presentation format"}
}

// IXFR is a meta record used (solely) in question sections to ask for an incremental zone transfer.
type IXFR struct {
	Hdr Header
}

func (rr *IXFR) Len() int       { return rr.Hdr.Len() }
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
	Hdr Header
	rdata.TSIG
}

func (rr *TSIG) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, rr.Algorithm, tsigTimeToString(rr.TimeSigned),
		strconv.Itoa(int(rr.Fudge)), strconv.Itoa(int(rr.MACSize)),
		strings.ToUpper(rr.MAC), strconv.Itoa(int(rr.OrigID)),
		strconv.Itoa(int(rr.Error)), strconv.Itoa(int(rr.OtherLen)), rr.OtherData)
	s := sb.String()
	builderPool.Put(*sb)
	return s
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
