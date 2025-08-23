package pack

import (
	"encoding/binary"
	"fmt"
)

// maybe this should all moved to cryptobyte as well...
// near future direction is clear all pack helpers should be here, not in msg_helpers.go

func Uint8(i uint8, msg []byte, off int) (off1 int, err error) {
	if off+1 > len(msg) {
		return len(msg), fmt.Errorf("overflow packing uint8")
	}
	msg[off] = i
	return off + 1, nil
}

func Uint16(i uint16, msg []byte, off int) (off1 int, err error) {
	if off+2 > len(msg) {
		return len(msg), fmt.Errorf("dns: overflow packing uint16")
	}
	binary.BigEndian.PutUint16(msg[off:], i)
	return off + 2, nil
}

func Uint32(i uint32, msg []byte, off int) (off1 int, err error) {
	if off+4 > len(msg) {
		return len(msg), fmt.Errorf("overflow packing uint32")
	}
	binary.BigEndian.PutUint32(msg[off:], i)
	return off + 4, nil
}

func Uint64(i uint64, msg []byte, off int) (off1 int, err error) {
	if off+8 > len(msg) {
		return len(msg), fmt.Errorf("overflow packing uint64")
	}
	binary.BigEndian.PutUint64(msg[off:], i)
	off += 8
	return off, nil
}

// StringAny packs a string as-is, no decoding or lenght bytes are written.
func StringAny(s string, msg []byte, off int) (int, error) {
	if off+len(s) > len(msg) {
		return len(msg), fmt.Errorf("overflow packing string anything")
	}
	copy(msg[off:off+len(s)], s)
	off += len(s)
	return off, nil
}
