package rdata

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

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

func (rr *TALINK) String() string {
	sb := builderPool.Get()
	sprintData(&sb, rr.PreviousName, rr.NextName)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *SSHFP) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.Algorithm)),
		strconv.Itoa(int(rr.Type)),
		strings.ToUpper(rr.FingerPrint))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *DNSKEY) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.Flags)),
		strconv.Itoa(int(rr.Protocol)),
		strconv.Itoa(int(rr.Algorithm)),
		rr.PublicKey)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *RKEY) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.Flags)),
		strconv.Itoa(int(rr.Protocol)),
		strconv.Itoa(int(rr.Algorithm)),
		rr.PublicKey)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *NSAPPTR) String() string { return rr.Ptr }

// TKEY has no official presentation format, but this will suffice.
func (rr *TKEY) String() string {
	sb := builderPool.Get()
	sprintData(&sb, rr.Algorithm,
		dnsutilTimeToString(rr.Inception),
		dnsutilTimeToString(rr.Expiration),
		strconv.Itoa(int(rr.Mode)),
		strconv.Itoa(int(rr.Error)),
		strconv.Itoa(int(rr.KeySize)),
		rr.Key,
		strconv.Itoa(int(rr.OtherLen)),
		rr.OtherData)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *RFC3597) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(len(rr.Data)/2), rr.Data)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *URI) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.Priority)), strconv.Itoa(int(rr.Weight)), sprintTxt([]string{rr.Target}))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *DHCID) String() string {
	sb := builderPool.Get()
	sb.WriteString(rr.Digest)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *TLSA) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.Usage)),
		strconv.Itoa(int(rr.Selector)),
		strconv.Itoa(int(rr.MatchingType)),
		rr.Certificate)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *SMIMEA) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.Usage)), strconv.Itoa(int(rr.Selector)), strconv.Itoa(int(rr.MatchingType)))

	// Every Nth char needs a space on this output. If we output
	// this as one giant line, we can't read it can in because in some cases
	// the cert length overflows scan.maxTok (2048).
	sx := splitN(rr.Certificate, 1024) // conservative value here
	sb.WriteByte(' ')
	sb.WriteString(strings.Join(sx, " "))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *HIP) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.PublicKeyAlgorithm)), rr.Hit, rr.PublicKey)
	for _, d := range rr.RendezvousServers {
		sb.WriteByte(' ')
		sb.WriteString(d)
	}
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *NINFO) String() string {
	sb := builderPool.Get()
	sb.WriteString(sprintTxt(rr.ZSData))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *NID) String() string {
	sb := builderPool.Get()
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
	builderPool.Put(sb)
	return s
}

func (rr *L32) String() string {
	sb := builderPool.Get()
	defer builderPool.Put(sb)
	sb.WriteString(strconv.Itoa(int(rr.Preference)))
	if !rr.Locator32.IsValid() {
		return sb.String()
	}
	sb.WriteByte(' ')
	sb.WriteString(rr.Locator32.String())
	return sb.String()
}

func (rr *L64) String() string {
	sb := builderPool.Get()
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
	builderPool.Put(sb)
	return s
}

func (rr *LP) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.Preference)), rr.Fqdn)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *EUI48) String() string { return euiToString(rr.Address, 48) }
func (rr *EUI64) String() string { return euiToString(rr.Address, 64) }

func (rr *CAA) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.Flag)), rr.Tag, sprintTxt([]string{rr.Value}))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *UID) String() string {
	sb := builderPool.Get()
	sb.WriteString(strconv.FormatInt(int64(rr.Uid), 10))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *GID) String() string {
	sb := builderPool.Get()
	sb.WriteString(strconv.FormatInt(int64(rr.Gid), 10))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *UINFO) String() string {
	sb := builderPool.Get()
	sb.WriteString(sprintTxt([]string{rr.Uinfo}))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *EID) String() string {
	sb := builderPool.Get()
	sb.WriteString(strings.ToUpper(rr.Endpoint))
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *NIMLOC) String() string {
	sb := builderPool.Get()
	sb.WriteString(rr.Locator)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *OPENPGPKEY) String() string {
	sb := builderPool.Get()
	sb.WriteString(rr.PublicKey)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *CSYNC) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.FormatInt(int64(rr.Serial), 10), strconv.Itoa(int(rr.Flags)))
	for _, t := range rr.TypeBitMap {
		sb.WriteByte(' ')
		sb.WriteString(typeToString(t))
	}
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *ZONEMD) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.Serial)), strconv.Itoa(int(rr.Scheme)), strconv.Itoa(int(rr.Hash)), rr.Digest)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr *SVCB) String() string {
	sb := builderPool.Get()
	sprintData(&sb, strconv.Itoa(int(rr.Priority)), rr.Target)
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
	builderPool.Put(sb)
	return s
}

func (rr *DELEG) String() string {
	sb := builderPool.Get()
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
	builderPool.Put(sb)
	return s
}

func (rr *DSYNC) String() string {
	sb := builderPool.Get()
	sb.WriteString(typeToString(rr.Type))
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
	builderPool.Put(sb)
	return s
}

func (rr *TSIG) String() string {
	sb := builderPool.Get()
	sprintData(&sb, rr.Algorithm, tsigTimeToString(rr.TimeSigned),
		strconv.Itoa(int(rr.Fudge)), strconv.Itoa(int(rr.MACSize)),
		strings.ToUpper(rr.MAC), strconv.Itoa(int(rr.OrigID)),
		strconv.Itoa(int(rr.Error)), strconv.Itoa(int(rr.OtherLen)), rr.OtherData)
	s := sb.String()
	builderPool.Put(sb)
	return s
}
