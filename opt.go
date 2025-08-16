package dns

func (*OPT) parse(c *zlexer, origin string) *ParseError {
	return &ParseError{err: "OPT records do not have a presentation format"}
}

// Version returns the EDNS version used. Only version zero is currently defined.
func (rr *OPT) Version() uint8 { return uint8(rr.Hdr.TTL & 0x00FF0000 >> 16) }

// SetVersion sets the version of EDNS. This is usually zero.
func (rr *OPT) SetVersion(v uint8) { rr.Hdr.TTL = rr.Hdr.TTL&0xFF00FFFF | uint32(v)<<16 }

// UDPSize returns the UDP buffer size.
func (rr *OPT) UDPSize() uint16 { return rr.Hdr.Class }

// SetUDPSize sets the UDP buffer size.
func (rr *OPT) SetUDPSize(size uint16) { rr.Hdr.Class = size }

// Security returns the value of the DO (DNSSEC OK) bit.
func (rr *OPT) Security() bool { return rr.Hdr.TTL&_DO == _DO }

// SetSecurity sets the security (DNSSEC OK) bit.
func (rr *OPT) SetSecurity(do bool) {
	if do {
		rr.Hdr.TTL |= _DO
	} else {
		rr.Hdr.TTL &^= _DO
	}
}

// CompactAnswers returns the value of the CO (Compact Answers OK) bit.
func (rr *OPT) CompactAnswers() bool { return rr.Hdr.TTL&_CO == _CO }

// SetCompactAnswers sets the CO (Compact Answers OK) bit.
func (rr *OPT) SetCompactAnswers(co bool) {
	if co {
		rr.Hdr.TTL |= _CO
	} else {
		rr.Hdr.TTL &^= _CO
	}
}

// Rcode returns the EDNS extended Rcode field (the upper 8 bits of the TTL).
func (rr *OPT) Rcode() uint16 {
	return uint16(rr.Hdr.TTL&0xFF000000>>24) << 4
}

// SetRcode sets the EDNS extended Rcode field.
// If the Rcode is not an extended Rcode, will reset the extended Rcode field to 0.
func (rr *OPT) SetRcode(v uint16) {
	rr.Hdr.TTL = rr.Hdr.TTL&0x00FFFFFF | uint32(v>>4)<<24
}

// Z returns the Z part of the OPT RR as a uint16 with only the 15 least significant bits used.
func (rr *OPT) Z() uint16 {
	return uint16(rr.Hdr.TTL & 0x3FFF)
}

// SetZ sets the Z part of the OPT RR, note only the 15 least significant bits of z are used.
func (rr *OPT) SetZ(z uint16) {
	rr.Hdr.TTL = rr.Hdr.TTL&^0x3FFF | uint32(z&0x3FFF)
}
