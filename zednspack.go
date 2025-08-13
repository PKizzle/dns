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

func (o *PADDING) unpack(s *cryptobyte.String) error {
	return nil
}

func (o *PADDING) pack(msg []byte, off int) (int, error) {
	return 0, nil
}
