package pack

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
)

// pack.Error

var base32HexNoPadEncoding = base32.HexEncoding.WithPadding(base32.NoPadding)

func fromBase32(s []byte) (buf []byte, err error) {
	for i, b := range s {
		if b >= 'a' && b <= 'z' {
			s[i] = b - 32
		}
	}
	buflen := base32HexNoPadEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base32HexNoPadEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}

func toBase32(b []byte) string {
	return base32HexNoPadEncoding.EncodeToString(b)
}

func fromBase64(s []byte) (buf []byte, err error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}

func toBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func Uint8(i uint8, msg []byte, off int) (off1 int, err error) {
	if off+1 > len(msg) {
		return len(msg), &Error{err: "overflow packing uint8"}
	}
	msg[off] = i
	return off + 1, nil
}

func Uint16(i uint16, msg []byte, off int) (off1 int, err error) {
	if off+2 > len(msg) {
		return len(msg), &Error{err: "overflow packing uint16"}
	}
	binary.BigEndian.PutUint16(msg[off:], i)
	return off + 2, nil
}

func Uint32(i uint32, msg []byte, off int) (off1 int, err error) {
	if off+4 > len(msg) {
		return len(msg), &Error{err: "overflow packing uint32"}
	}
	binary.BigEndian.PutUint32(msg[off:], i)
	return off + 4, nil
}

func Uint48(i uint64, msg []byte, off int) (off1 int, err error) {
	if off+6 > len(msg) {
		return len(msg), &Error{err: "overflow packing uint64 as uint48"}
	}
	msg[off] = byte(i >> 40)
	msg[off+1] = byte(i >> 32)
	msg[off+2] = byte(i >> 24)
	msg[off+3] = byte(i >> 16)
	msg[off+4] = byte(i >> 8)
	msg[off+5] = byte(i)
	off += 6
	return off, nil
}

func Uint64(i uint64, msg []byte, off int) (off1 int, err error) {
	if off+8 > len(msg) {
		return len(msg), &Error{err: "overflow packing uint64"}
	}
	binary.BigEndian.PutUint64(msg[off:], i)
	off += 8
	return off, nil
}

func String(s string, msg []byte, off int) (int, error) {
	off, err := packTxtString(s, msg, off)
	if err != nil {
		return len(msg), err
	}
	return off, nil
}

func StringBase32(s string, msg []byte, off int) (int, error) {
	b32, err := fromBase32([]byte(s))
	if err != nil {
		return len(msg), err
	}
	if off+len(b32) > len(msg) {
		return len(msg), &Error{err: "overflow packing base32"}
	}
	copy(msg[off:off+len(b32)], b32)
	off += len(b32)
	return off, nil
}

func StringBase64(s string, msg []byte, off int) (int, error) {
	b64, err := fromBase64([]byte(s))
	if err != nil {
		return len(msg), err
	}
	if off+len(b64) > len(msg) {
		return len(msg), &Error{err: "overflow packing base64"}
	}
	copy(msg[off:off+len(b64)], b64)
	off += len(b64)
	return off, nil
}

func StringHex(s string, msg []byte, off int) (int, error) {
	h, err := hex.DecodeString(s)
	if err != nil {
		return len(msg), err
	}
	if off+len(h) > len(msg) {
		return len(msg), &Error{err: "overflow packing hex"}
	}
	copy(msg[off:off+len(h)], h)
	off += len(h)
	return off, nil
}

func StringAny(s string, msg []byte, off int) (int, error) {
	if off+len(s) > len(msg) {
		return len(msg), &Error{err: "overflow packing anything"}
	}
	copy(msg[off:off+len(s)], s)
	off += len(s)
	return off, nil
}
