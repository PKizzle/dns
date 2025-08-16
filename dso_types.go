package dns

import "fmt"

// DSO option codes. All DSO types and constants in this package carry the Stateful prefix.
const (
	StatefulNone              uint16 = 0x0
	StatefulKEEPALIVE         uint16 = 0x1
	StatefulRETRYDELAY        uint16 = 0x2
	StatefulENCRYPTIONPADDING uint16 = 0x3
)

// for string we want to be able parse them with New().

// KEEPALIVE impleemnts  RFC 8490, Section 7.1: Keepalive TLV.
//
// This record must be put in the stateful section.
type KEEPALIVE struct {
	InactivityTimeout uint32
	KeepAliveInterval uint32
}

func (d *KEEPALIVE) String() string {
	return fmt.Sprintf("timeout %dms, interval %dms", d.InactivityTimeout, d.KeepAliveInterval)
}
