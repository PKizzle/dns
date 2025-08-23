package dns

// should be generated, it is not...

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"

	"codeberg.org/miekg/dns/internal/pack"
	"codeberg.org/miekg/dns/internal/unpack"
	"golang.org/x/crypto/cryptobyte"
)

func (o *LLQ) pack(msg []byte, off int) (off1 int, err error) {
	off, err = pack.Uint16(o.Version, msg, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint16(o.Opcode, msg, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint16(o.Error, msg, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint64(o.ID, msg, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint32(o.LeaseLife, msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (o *LLQ) unpack(s *cryptobyte.String) error {
	if !s.ReadUint16(&o.Version) {
		return ErrUnpackOverflow
	}
	if !s.ReadUint16(&o.Opcode) {
		return ErrUnpackOverflow
	}
	if !s.ReadUint16(&o.Error) {
		return ErrUnpackOverflow
	}
	if !s.ReadUint64(&o.ID) {
		return ErrUnpackOverflow
	}
	if !s.ReadUint32(&o.LeaseLife) {
		return ErrUnpackOverflow
	}
	return nil
}

func (o *NSID) unpack(s *cryptobyte.String) error {
	o.Nsid = hex.EncodeToString(*s)
	return nil
}

func (o *NSID) pack(msg []byte, off int) (int, error) {
	return hex.Decode(msg[off:], []byte(o.Nsid))
}

func (o *COOKIE) pack(msg []byte, off int) (int, error) {
	return hex.Decode(msg[off:], []byte(o.Cookie))
}

func (o *COOKIE) unpack(s *cryptobyte.String) error {
	o.Cookie = hex.EncodeToString(*s)
	return nil
}

func (o *PADDING) unpack(s *cryptobyte.String) error {
	return nil
}

func (o *PADDING) pack(msg []byte, off int) (int, error) {
	return 0, nil
}

func (o *DAU) pack(msg []byte, off int) (off1 int, err error) {
	for i := range o.AlgCode {
		if off, err = pack.Uint8(o.AlgCode[i], msg, off); err != nil {
			return off, err
		}
	}
	return off, nil
}

func (o *DAU) unpack(s *cryptobyte.String) error {
	for !s.Empty() {
		var a uint8
		s.ReadUint8(&a)
		o.AlgCode = append(o.AlgCode, a)
	}
	return nil
}

func (o *DHU) pack(msg []byte, off int) (off1 int, err error) {
	for i := range o.AlgCode {
		if off, err = pack.Uint8(o.AlgCode[i], msg, off); err != nil {
			return off, err
		}
	}
	return off, nil
}

func (o *DHU) unpack(s *cryptobyte.String) error {
	for !s.Empty() {
		var a uint8
		s.ReadUint8(&a)
		o.AlgCode = append(o.AlgCode, a)
	}
	return nil
}

func (o *N3U) pack(msg []byte, off int) (off1 int, err error) {
	for i := range o.AlgCode {
		if off, err = pack.Uint8(o.AlgCode[i], msg, off); err != nil {
			return off, err
		}
	}
	return off, nil
}

func (o *N3U) unpack(s *cryptobyte.String) error {
	for !s.Empty() {
		var a uint8
		s.ReadUint8(&a)
		o.AlgCode = append(o.AlgCode, a)
	}
	return nil
}

func (o *EDE) unpack(s *cryptobyte.String) (err error) {
	if !s.ReadUint16(&o.InfoCode) {
		return ErrUnpackOverflow
	}
	if o.ExtraText, err = unpack.StringAny(s, len(*s)); err != nil {
		return ErrUnpackOverflow.Fmt(": %s", "EDE option")
	}
	return nil
}

func (o *EDE) pack(msg []byte, off int) (int, error) {
	off, err := pack.Uint16(o.InfoCode, msg, off)
	if err != nil {
		return off, err
	}
	o.ExtraText = string(msg[off:])
	return off, nil
}

func (e *REPORTING) unpack(s *cryptobyte.String) (err error) {
	e.AgentDomain, err = unpackName(s, nil) // TODO: unpackNAme with nil buffer, no compression pointers..
	if err != nil {
		return ErrUnpackOverflow.Fmt(": %s", "REPORTING agent domain")
	}
	return nil
}

func (e *REPORTING) pack(msg []byte, off int) (int, error) {
	off, err := packName(e.AgentDomain, msg, off, nil, false)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (o *EXPIRE) pack(msg []byte, off int) (int, error) {
	if o.Expire == 0 {
		return off, nil
	}
	return pack.Uint32(o.Expire, msg, off)
}

func (o *EXPIRE) unpack(s *cryptobyte.String) error {
	if s.Empty() { // zero-length EXPIRE query, see RFC 7314 Section 2
		o.Expire = 0
		return nil
	}
	if !s.ReadUint32(&o.Expire) {
		return ErrUnpackOverflow
	}
	return nil
}

func (o *TCPKEEPALIVE) pack(msg []byte, off int) (int, error) {
	if o.Timeout > 0 {
		return pack.Uint16(o.Timeout, msg, off)
	}
	return off, nil
}

func (o *TCPKEEPALIVE) unpack(s *cryptobyte.String) error {
	if s.Empty() {
		return nil
	}
	if !s.ReadUint16(&o.Timeout) {
		return ErrUnpackOverflow
	}
	return nil
}

func (o *SUBNET) pack(msg []byte, off int) (int, error) {
	binary.BigEndian.PutUint16(msg[off:], o.Family)
	off += 2
	msg[off] = o.SourceNetmask
	off++
	msg[off] = o.SourceScope
	off++
	switch o.Family {
	case 1:
		msg[off] = 32
	case 2:
		msg[off] = 128
	default:
		return off, errors.New("dns: bad address family")
	}
	return off, nil
}

func (o *SUBNET) unpack(s *cryptobyte.String) (err error) {
	if !s.ReadUint16(&o.Family) {
		return ErrUnpackOverflow
	}
	if !s.ReadUint8(&o.SourceNetmask) {
		return ErrUnpackOverflow
	}
	if !s.ReadUint8(&o.SourceScope) {
		return ErrUnpackOverflow
	}
	switch o.Family {
	case 0:
		o.Address = net.IPv4(0, 0, 0, 0)
	case 1:
		o.Address, err = unpack.A(s)
	case 2:
		o.Address, err = unpack.AAAA(s)
	default:
		return errors.New("dns: bad address family")
	}
	return nil
}

func (o *ESU) pack(msg []byte, off int) (int, error) {
	return packOctetString(o.URI, msg, off)
}

func (o *ESU) unpack(s *cryptobyte.String) (err error) {
	o.URI, err = unpackStringOctet(s)
	return err
}
