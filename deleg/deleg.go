// Package deleg deals with all the intricacies of the DELEG RR. All the sub-types ([Infos]) used in the RR are defined here.
// As DELEG is derived from the [dns.SVCB] RR so there are a lot of similarities.
package deleg

import (
	"net"
	"slices"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns/internal/reverse"
)

// Keys as defined in the DELEG draft.
const (
	KeyReserved uint16 = 0

	KeyServerIP4 uint16 = iota + 1
	KeyServerIP6
	KeyServerName
	KeyIncludeName
)

// Info defines a key=value pair for the DELEG/DELEGI RR type. A DELEG RR can have multiple infos appended to it.
// The numerical key code is derived from the type, see [InfoToKey].
type Info interface {
	String() string // String returns the string representation of the value.
	Len() int       // Len returns the length of value in the wire format.
	Copy() Info     // Copy returns a deep copy of the Info.
}

// KeyToString return the string representation for k.  For KeyReserved the empty string is returned. For
// unknown keys "key"+value is returned, see section 2.1 of RFC 9460.
func KeyToString(k uint16) string {
	if k == KeyReserved {
		return ""
	}
	if s, ok := keyToString[k]; ok {
		return s
	}
	return "key" + strconv.Itoa(int(k))
}

var keyToString = map[uint16]string{
	KeyServerIP4:   "server-ip4",
	KeyServerIP6:   "server-ip6",
	KeyServerName:  "server-name",
	KeyIncludeName: "include-name",
}

// StringtoKey is the reverse of KeyToString and takes keyXXXX into account.
func StringToKey(s string) uint16 {
	if k, ok := stringToKey[s]; ok {
		return k
	}
	if strings.HasPrefix(s, "key") {
		k, _ := strconv.Atoi(s[3:])
		return uint16(k)
	}
	return KeyReserved
}

var stringToKey = reverse.Int16(keyToString)

// KeyToInfo convert the key value to a Info.
func KeyToInfo(k uint16) func() Info {
	switch k {
	case KeyServerIP4:
		return func() Info { return new(SERVERIP4) }
	case KeyServerIP6:
		return func() Info { return new(SERVERIP6) }
	default:
		return nil
	}
}

// InfoToKey is the reverse of KeyToInfo.
func InfoToKey(i Info) uint16 {
	switch i.(type) {
	case *SERVERIP4:
		return KeyServerIP4
	case *SERVERIP6:
		return KeyServerIP6
	}
	return KeyReserved
}

// SERVERIP4 info adds IPv4 addresses to the DELEG RR.
type SERVERIP4 struct {
	IPs []net.IP
}

func (s *SERVERIP4) Len() int { return tlv + 4*len(s.IPs) }

func (s *SERVERIP4) String() string {
	str := make([]string, len(s.IPs))
	for i, e := range s.IPs {
		x := e.To4()
		if x == nil {
			return "<nil>"
		}
		str[i] = x.String()
	}
	return strings.Join(str, ",")
}

// SERVERIP6 info adds IPv6 addresses to the DELEG RR.
type SERVERIP6 struct {
	IPs []net.IP
}

func (s *SERVERIP6) Len() int { return tlv + 16*len(s.IPs) }

func (s *SERVERIP6) String() string {
	str := make([]string, len(s.IPs))
	for i, e := range s.IPs {
		x := e.To4()
		if x == nil {
			return "<nil>"
		}
		str[i] = x.String()
	}
	return strings.Join(str, ",")
}

const tlv = 4

func (s *SERVERIP4) Copy() Info { return &SERVERIP4{slices.Clone(s.IPs)} }
func (s *SERVERIP6) Copy() Info { return &SERVERIP4{slices.Clone(s.IPs)} }
