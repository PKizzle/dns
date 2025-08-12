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
