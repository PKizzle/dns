// Package jump contain mini pack function that quick jumping through a binary message.
package jump

import "encoding/binary"

// Main use is to find the last RR in a message for TSIG.

// Name jumps the name that should start msgBuf[off].
func Name(msgBuf []byte, off int) int {
	for off < len(msgBuf) {
		c := msgBuf[off]
		off++

		switch c & 0xC0 {
		case 0x00:
			if c == 0 {
				return off
			}
			off += int(c)
		case 0xC0:
			return off + 1
		}
	}
	return 0
}

// Question jumps the question section that should start at msgBuf[off].
func Question(msgBuf []byte, off int) int {
	off = Name(msgBuf, off)
	if off > len(msgBuf) {
		return 0
	}
	return off + 4 // type + class
}

// RR jumps the RR that starts at msgBuf[off].
func RR(msgBuf []byte, off int) int {
	off = Name(msgBuf, off)
	if off > len(msgBuf) {
		return 0
	}
	off += 8                 // type + class + ttl
	if off+2 > len(msgBuf) { // not enough room to read rdlength
		return 0
	}
	rdlength := binary.BigEndian.Uint16(msgBuf[off:])
	println("READ RDLENGTH", rdlength, "at", off)
	println(off+2+int(rdlength), off, 2, rdlength)
	off = off + 2 + int(rdlength)
	println("RETTING", off)
	return off
}

// To jumps to the start of the i-th RR in the message, that start at msgBuf[0]. This counts from 0 which
// return the RR after the question section. When we jump over the message 0 is returned.
func To(i int, msgBuf []byte) int {
	off := 12
	if off > len(msgBuf) {
		return 0
	}
	off = Question(msgBuf, off)
	if off > len(msgBuf) {
		return 0
	}
	for range i {
		off = RR(msgBuf, off)
		println(off)
		if off > len(msgBuf) {
			return 0
		}
	}
	return off
}
