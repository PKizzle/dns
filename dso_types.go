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

// KEEPALIVE, see RFC 8490, section 7.1.
//
// This record must be put in the stateful section.
type KEEPALIVE struct {
	Timeout  uint32
	Interval uint32
}

func (d *KEEPALIVE) String() string {
	return fmt.Sprintf("timeout %dms, interval %dms", d.Timeout, d.Interval)
}

// RETRYDELAY, see RFC 8490, section 7.2.
//
// This record must be put in the stateful section.
type RETRYDELAY struct {
	Delay uint32
}

func (d *RETRYDELAY) String() string {
	return fmt.Sprintf("delay %dms", d.Delay)
}

// DPADDING option is used to add padding. See section 7.3.
//
// This record must be put in the stateful section.
type DPADDING struct {
	Padding string `dns:"octet"`
}

func (d *DPADDING) String() string {
	return fmt.Sprintf("padding %s", d.Padding)
}
