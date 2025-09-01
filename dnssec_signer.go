package dns

import (
	"math/big"

	"codeberg.org/miekg/dns/internal/pack"
)

// canonicalize will put the RR in Canonical form, see RFC 4034: 6.2.  Canonical RR Form. (2) - domain name to lowercase
// This changes the RR itself.
func canonicalize(rr RR) {
	// RFC 4034: 6.2.  Canonical RR Form. (2) - domain name to lowercase
	rr.Header().Name = dnsutilCanonical(rr.Header().Name)
	// 6.2. Canonical RR Form. (3) - domain rdata to lowercase.
	//   NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR,
	//   HINFO, MINFO, MX, RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX,
	//   SRV, DNAME, A6
	//
	// RFC 6840 - Clarifications and Implementation Notes for DNS Security (DNSSEC):
	//	Section 6.2 of [RFC4034] also erroneously lists HINFO as a record
	//	that needs conversion to lowercase, and twice at that.  Since HINFO
	//	records contain no domain names, they are not subject to case
	//	conversion.
	switch x := rr.(type) {
	case *NS:
		x.Ns = dnsutilCanonical(x.Ns)
	case *MD:
		x.Md = dnsutilCanonical(x.Md)
	case *MF:
		x.Mf = dnsutilCanonical(x.Mf)
	case *CNAME:
		x.Target = dnsutilCanonical(x.Target)
	case *SOA:
		x.Ns = dnsutilCanonical(x.Ns)
		x.Mbox = dnsutilCanonical(x.Mbox)
	case *MB:
		x.Mb = dnsutilCanonical(x.Mb)
	case *MG:
		x.Mg = dnsutilCanonical(x.Mg)
	case *MR:
		x.Mr = dnsutilCanonical(x.Mr)
	case *PTR:
		x.Ptr = dnsutilCanonical(x.Ptr)
	case *MINFO:
		x.Rmail = dnsutilCanonical(x.Rmail)
		x.Email = dnsutilCanonical(x.Email)
	case *MX:
		x.Mx = dnsutilCanonical(x.Mx)
	case *RP:
		x.Mbox = dnsutilCanonical(x.Mbox)
		x.Txt = dnsutilCanonical(x.Txt)
	case *AFSDB:
		x.Hostname = dnsutilCanonical(x.Hostname)
	case *RT:
		x.Host = dnsutilCanonical(x.Host)
	case *PX:
		x.Map822 = dnsutilCanonical(x.Map822)
		x.Mapx400 = dnsutilCanonical(x.Mapx400)
	case *NAPTR:
		x.Replacement = dnsutilCanonical(x.Replacement)
	case *KX:
		x.Exchanger = dnsutilCanonical(x.Exchanger)
	case *SRV:
		x.Target = dnsutilCanonical(x.Target)
	case *DNAME:
		x.Target = dnsutilCanonical(x.Target)
	}
}

// The RRSIG needs to be converted to wireformat with some of the rdata (the signature) missing.
type rrsigWireFmt struct {
	TypeCovered uint16
	Algorithm   uint8
	Labels      uint8
	OrigTTL     uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	SignerName  string `dns:"domain-name"`
	/* No Signature */
}

// Used for converting DNSKEY's rdata to wirefmt.
type dnskeyWireFmt struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey string `dns:"base64"`
	/* Nothing is left out */
}

func (sw *rrsigWireFmt) pack(buf []byte) (int, error) {
	// copied from zmsg.go RRSIG packing
	off, err := pack.Uint16(sw.TypeCovered, buf, 0)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint8(sw.Algorithm, buf, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint8(sw.Labels, buf, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint32(sw.OrigTTL, buf, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint32(sw.Expiration, buf, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint32(sw.Inception, buf, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint16(sw.KeyTag, buf, off)
	if err != nil {
		return off, err
	}
	return pack.Name(sw.SignerName, buf, off, nil, false)
}

func (dw *dnskeyWireFmt) pack(buf []byte) (int, error) {
	// copied from zmsg.go DNSKEY packing
	off, err := pack.Uint16(dw.Flags, buf, 0)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint8(dw.Protocol, buf, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint8(dw.Algorithm, buf, off)
	if err != nil {
		return off, err
	}
	return pack.StringBase64(dw.PublicKey, buf, off)
}

// Helper function for packing and unpacking
func intToBytes(i *big.Int, length int) []byte {
	buf := i.Bytes()
	if len(buf) < length {
		b := make([]byte, length)
		copy(b[length-len(buf):], buf)
		return b
	}
	return buf
}
