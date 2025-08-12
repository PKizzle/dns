package dns

// IsRRset reports whether a set of RRs is a valid RRset as defined by RFC 2181.
// This means the RRs need to have the same type, name, and class.
func IsRRset(rrset []RR) bool {
	if len(rrset) == 0 {
		return false
	}

	base := rrset[0].Header()
	basetype := RRToType(rrset[0])
	for _, rr := range rrset[1:] {
		h := rr.Header()
		htype := RRToType(rr)
		if htype != basetype || h.Class != base.Class || h.Name != base.Name {
			return false
		}
	}

	return true
}

// SetReply creates a reply message from a request message.
func (m *Msg) SetReply(r *Msg) *Msg {
	m.ID = r.ID
	m.Response = true
	m.Opcode = m.Opcode
	if m.Opcode == OpcodeQuery {
		// more??
		m.RecursionDesired = r.RecursionDesired
		m.CheckingDisabled = r.CheckingDisabled
	}
	m.Rcode = RcodeSuccess
	m.Question = r.Question
	return m
}
