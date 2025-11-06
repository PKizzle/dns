package dnsutil

import (
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"

	"codeberg.org/miekg/dns/internal/pack"
)

// NSEC3Name returns the hashed label according to RFC 5155.
func NSEC3Name(label, salt string, iter uint16) string {
	hashdata := make([]byte, hex.DecodedLen(len(salt))+255)
	n, err := pack.StringHex(salt, hashdata, 0)
	if err != nil {
		return ""
	}
	m, err := pack.Name(label, hashdata[n:], 0, nil, false)
	if err != nil {
		return ""
	}
	hashdata = hashdata[:n+m]

	s := sha1.New()
	var nsec3 []byte
	for k := uint16(0); k < iter+1; k++ {
		s.Reset()
		s.Write(hashdata)
		nsec3 = s.Sum(nil)
	}
	return base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(nsec3)
}
