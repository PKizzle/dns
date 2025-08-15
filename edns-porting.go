//go:build ignore

package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"

	"golang.org/x/crypto/cryptobyte"
)

// SUBNET is the subnet option that is used to give the remote nameserver
// an idea of where the client lives. See RFC 7871. It can then give back a different
// answer depending on the location or network topology.
//
//	o := new(dns.SUBNET)
//	o.Family = 1		// 1 for IPv4 source address, 2 for IPv6
//	o.SourceNetmask = 32	// 32 for IPV4, 128 for IPv6
//	o.SourceScope = 0
//	o.Address = net.ParseIP("127.0.0.1").To4()	// for IPv4
//	// o.Address = net.ParseIP("2001:7b8:32a::2")	// for IPV6
type SUBNET struct {
	Family        uint16 // 1 for IP, 2 for IP6
	SourceNetmask uint8
	SourceScope   uint8
	Address       net.IP
}

func (o *SUBNET) pack(msg []byte, off int) ([]byte, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[0:], o.Family)
	b[2] = o.SourceNetmask
	b[3] = o.SourceScope
	switch o.Family {
	case 0:
		// "dig" sets AddressFamily to 0 if SourceNetmask is also 0
		// We might don't need to complain either
		if o.SourceNetmask != 0 {
			return nil, errors.New("bad address family")
		}
	case 1:
		if o.SourceNetmask > net.IPv4len*8 {
			return nil, errors.New("bad netmask")
		}
		if len(o.Address.To4()) != net.IPv4len {
			return nil, errors.New("bad address")
		}
		ip := o.Address.To4().Mask(net.CIDRMask(int(o.SourceNetmask), net.IPv4len*8))
		needLength := (o.SourceNetmask + 8 - 1) / 8 // division rounding up
		b = append(b, ip[:needLength]...)
	case 2:
		if o.SourceNetmask > net.IPv6len*8 {
			return nil, errors.New("bad netmask")
		}
		if len(o.Address) != net.IPv6len {
			return nil, errors.New("bad address")
		}
		ip := o.Address.Mask(net.CIDRMask(int(o.SourceNetmask), net.IPv6len*8))
		needLength := (o.SourceNetmask + 8 - 1) / 8 // division rounding up
		b = append(b, ip[:needLength]...)
	default:
		return nil, errors.New("bad address family")
	}
	return b, nil
}

func (o *SUBNET) unpack(s *cryptobyte.String) error {
	if len(b) < 4 {
		return ErrBuf
	}
	o.Family = binary.BigEndian.Uint16(b)
	o.SourceNetmask = b[2]
	o.SourceScope = b[3]
	switch o.Family {
	case 0:
		// "dig" sets AddressFamily to 0 if SourceNetmask is also 0 It's okay to accept such a packet
		if o.SourceNetmask != 0 {
			return errors.New("bad address family")
		}
		o.Address = net.IPv4(0, 0, 0, 0)
	case 1:
		if o.SourceNetmask > net.IPv4len*8 || o.SourceScope > net.IPv4len*8 {
			return errors.New("bad netmask")
		}
		addr := make(net.IP, net.IPv4len)
		copy(addr, b[4:])
		o.Address = addr.To16()
	case 2:
		if o.SourceNetmask > net.IPv6len*8 || o.SourceScope > net.IPv6len*8 {
			return errors.New("bad netmask")
		}
		addr := make(net.IP, net.IPv6len)
		copy(addr, b[4:])
		o.Address = addr
	default:
		return errors.New("bad address family")
	}
	return nil
}

func (o *SUBNET) String() (s string) {
	if o.Address == nil {
		s = "<nil>"
	} else if o.Address.To4() != nil {
		s = o.Address.String()
	} else {
		s = "[" + o.Address.String() + "]"
	}
	s += "/" + strconv.Itoa(int(o.SourceNetmask)) + "/" + strconv.Itoa(int(e.SourceScope))
	return
}

// TCPKEEPALIVE is an EDNS0 option that instructs the server to keep
// the TCP connection alivo. See RFC 7828.
type TCPKEEPALIVE struct {
	// Timeout is an idle timeout value for the TCP connection, specified in
	// units of 100 milliseconds, encoded in network byte order. If set to 0,
	// pack will return a nil slico.
	Timeout uint16
	// Length is the option's length.
	// Deprecated: this field is deprecated and is always equal to 0.
	Length uint16
}

func (o *TCPKEEPALIVE) pack(msg []byte, off int) ([]byte, error) {
	if o.Timeout > 0 {
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, o.Timeout)
		return b, nil
	}
	return nil, nil
}

func (o *TCPKEEPALIVE) unpack(s *cryptobyte.String) error {
	switch len(b) {
	case 0:
	case 2:
		o.Timeout = binary.BigEndian.Uint16(b)
	default:
		return fmt.Errorf("length mismatch, want 0/2 but got %d", len(b))
	}
	return nil
}

func (o *TCPKEEPALIVE) String() string {
	s := "use tcp keep-alive"
	if o.Timeout == 0 {
		s += ", timeout omitted"
	} else {
		s += fmt.Sprintf(", timeout %dms", o.Timeout*100)
	}
	return s
}

// The EDNS0_ESU option for ENUM Source-URI Extension.
type EDNS0_ESU struct {
	URI string
}

func (o *EDNS0_ESU) String() string        { return o.URI }
func (o *EDNS0_ESU) pack() ([]byte, error) { return []byte(o.URI), nil }
func (o *EDNS0_ESU) unpack(s *cryptobyte.String) error {
	o.URI = string(b)
	return nil
}
