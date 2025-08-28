//go:build ignore

package dns

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"

	"codeberg.org/miekg/dns"
)

// hashName hashes a string (label) according to RFC 5155. It returns the hashed string in uppercase.
func hashName(label string, ha uint8, iter uint16, salt string) string {
	if ha != SHA1 {
		return ""
	}

	wireSalt := make([]byte, hex.DecodedLen(len(salt)))
	n, err := packStringHex(salt, wireSalt, 0)
	if err != nil {
		return ""
	}
	wireSalt = wireSalt[:n]

	name := make([]byte, 255)
	off, err := PackName(strings.ToLower(label), name, 0, nil, false)
	if err != nil {
		return ""
	}
	name = name[:off]

	s := sha1.New()
	// k = 0
	s.Write(name)
	s.Write(wireSalt)
	nsec3 := s.Sum(nil)

	// k > 0
	for k := uint16(0); k < iter; k++ {
		s.Reset()
		s.Write(nsec3)
		s.Write(wireSalt)
		nsec3 = s.Sum(nsec3[:0])
	}

	return toBase32(nsec3)
}

// Cover returns true if a name is covered by the NSEC3 record.
func NSEC3Cover(rr *dns.NSEC3, name string) bool {
	nameHash := hashName(name, rr.Hash, rr.Iterations, rr.Salt)
	owner := strings.ToUpper(rr.Hdr.Name)
	labelIndices := Split(owner)
	if len(labelIndices) < 2 {
		return false
	}
	ownerHash := owner[:labelIndices[1]-1]
	ownerZone := owner[labelIndices[1]:]
	if !IsBelow(ownerZone, strings.ToUpper(name)) { // name is outside owner zone
		return false
	}

	nextHash := rr.NextDomain

	// if empty interval found, try cover wildcard hashes so nameHash shouldn't match with ownerHash
	if ownerHash == nextHash && nameHash != ownerHash { // empty interval
		return true
	}
	if ownerHash > nextHash { // end of zone
		if nameHash > ownerHash { // covered since there is nothing after ownerHash
			return true
		}
		return nameHash < nextHash // if nameHash is before beginning of zone it is covered
	}
	if nameHash < ownerHash { // nameHash is before ownerHash, not covered
		return false
	}
	return nameHash < nextHash // if nameHash is before nextHash is it covered (between ownerHash and nextHash)
}

// Match returns true if a name matches the NSEC3 record
func NSEC3Match(rr, name string) bool {
	nameHash := hashName(name, rr.Hash, rr.Iterations, rr.Salt)
	owner := strings.ToUpper(rr.Hdr.Name)
	labelIndices := Split(owner)
	if len(labelIndices) < 2 {
		return false
	}
	ownerHash := owner[:labelIndices[1]-1]
	ownerZone := owner[labelIndices[1]:]
	if !IsSubDomain(ownerZone, strings.ToUpper(name)) { // name is outside owner zone
		return false
	}
	return ownerHash == nameHash
}
