package dns

import "golang.org/x/crypto/cryptobyte"

// EDNS0Coder is an interface for custom EDNS0 options defined outside this package.
// It enables external packages to implement custom EDNS0 option types that can be
// serialized to and from DNS wire format without modifying the library code.
//
// To create a custom EDNS0 option, your type must implement three interfaces:
//
//  1. EDNS0 interface (which embeds RR) - provides Header(), Pseudo(), Len(), String(), and Clone()
//  2. Typer interface - provides Type() to return the EDNS0 option code
//  3. EDNS0Coder interface (this interface) - provides Pack() and Unpack() for wire format serialization
//
// Additionally, you must register your option in the global maps:
//
//	dns.CodeToRR[myCode] = func() dns.EDNS0 { return new(MyOption) }
//	dns.CodeToString[myCode] = "MYOPTION"
//
// StringToCode is automatically generated from CodeToString via reverse mapping.
//
// Example implementation:
//
//	// Define custom EDNS0 option type
//	type MyOption struct {
//	    Data string
//	}
//
//	// EDNS0 interface methods
//	func (o *MyOption) Header() *dns.Header { return &dns.Header{Name: "."} }
//	func (o *MyOption) Pseudo() bool { return true }
//	func (o *MyOption) Len() int { return 4 + len(o.Data) } // 4 = tlv overhead
//	func (o *MyOption) String() string { return "MYOPTION " + o.Data }
//	func (o *MyOption) Clone() dns.RR {
//	    return &MyOption{Data: o.Data}
//	}
//
//	// Typer interface
//	func (o *MyOption) Type() uint16 { return 0xFDE9 } // Use local/experimental range
//
//	// EDNS0Coder interface
//	func (o *MyOption) Pack(msg []byte, off int) (int, error) {
//	    if off+len(o.Data) > len(msg) {
//	        return len(msg), dns.ErrBuf
//	    }
//	    copy(msg[off:], o.Data)
//	    return off + len(o.Data), nil
//	}
//
//	func (o *MyOption) Unpack(s *cryptobyte.String) error {
//	    data := make([]byte, len(*s))
//	    if !s.CopyBytes(data) {
//	        return fmt.Errorf("failed to unpack MyOption")
//	    }
//	    o.Data = string(data)
//	    return nil
//	}
//
//	// Registration (do this once, e.g., in init())
//	func init() {
//	    dns.CodeToRR[0xFDE9] = func() dns.EDNS0 { return new(MyOption) }
//	    dns.CodeToString[0xFDE9] = "MYOPTION"
//	}
//
type EDNS0Coder interface {
	// Pack encodes the EDNS0 option data into wire format at the specified offset in msg.
	// It should only pack the option's data, not the 4-byte TLV header (type and length).
	// Returns the new offset after packing and any error encountered.
	Pack(msg []byte, off int) (int, error)

	// Unpack decodes the EDNS0 option data from wire format.
	// The cryptobyte.String contains only the option's data, not the TLV header.
	// Returns any error encountered during unpacking.
	Unpack(s *cryptobyte.String) error
}
