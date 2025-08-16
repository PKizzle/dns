package dns

import (
	"encoding/hex"

	"golang.org/x/crypto/cryptobyte"
)

func (o *LLQ) pack(msg []byte, off int) (off1 int, err error) {
	off, err = packUint16(o.Version, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(o.Opcode, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(o.Error, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint64(o.ID, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint32(o.LeaseLife, msg, off)
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
		if off, err = packUint8(o.AlgCode[i], msg, off); err != nil {
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
		if off, err = packUint8(o.AlgCode[i], msg, off); err != nil {
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
		if off, err = packUint8(o.AlgCode[i], msg, off); err != nil {
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
	if o.ExtraText, err = unpackStringAny(s, len(*s)); err != nil {
		return ErrUnpackOverflow.Fmt(": %s", "EDE option")
	}
	return nil
}

func (o *EDE) pack(msg []byte, off int) (int, error) {
	off, err := packUint16(o.InfoCode, msg, off)
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
	return packUint32(o.Expire, msg, off)
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
		return packUint16(o.Timeout, msg, off)
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
