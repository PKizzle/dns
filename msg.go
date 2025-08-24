package dns

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns/internal/ddd"
	"codeberg.org/miekg/dns/internal/pack"
	"golang.org/x/crypto/cryptobyte"
)

const (
	maxCompressionOffset    = 2 << 13 // We have 14 bits for the compression pointer
	maxDomainNameWireOctets = 255     // See RFC 1035 section 2.3.4

	// This is the maximum length of a domain name in presentation format. The
	// maximum wire length of a domain name is 255 octets (see above), with the
	// maximum label length being 63. The wire format requires one extra byte over
	// the presentation format, reducing the number of octets by 1. Each label in
	// the name will be separated by a single period, with each octet in the label
	// expanding to at most 4 bytes (\DDD). If all other labels are of the maximum
	// length, then the final label can only be 61 octets long to not exceed the
	// maximum allowed wire length.
	maxDomainNamePresentationLength = 61*4 + 1 + 63*4 + 1 + 63*4 + 1 + 63*4 + 1
)

// ID by default returns a 16-bit random number to be used as a message id. The
// number is drawn from a cryptographically secure random number generator.
// This being a variable the function can be reassigned to a custom function.
// For instance, to make it return a static value for testing:
//
//	dns.ID = func() uint16 { return 3 }
var ID = id

// id returns a 16 bits random number to be used as a
// message id. The random provided should be good enough.
func id() uint16 {
	var output uint16
	err := binary.Read(rand.Reader, binary.BigEndian, &output)
	if err != nil {
		panic("dns: reading random id failed: " + err.Error())
	}
	return output
}

// ClassToString is a maps Classes to strings for each CLASS wire type.
var ClassToString = map[uint16]string{
	ClassINET:   "IN",
	ClassCSNET:  "CS",
	ClassCHAOS:  "CH",
	ClassHESIOD: "HS",
	ClassNONE:   "NONE",
	ClassANY:    "ANY",
}

// OpcodeToString maps Opcodes to strings.
var OpcodeToString = map[uint8]string{
	OpcodeQuery:    "QUERY",
	OpcodeIQuery:   "IQUERY",
	OpcodeStatus:   "STATUS",
	OpcodeNotify:   "NOTIFY",
	OpcodeUpdate:   "UPDATE",
	OpcodeStateful: "STATEFUL",
}

// RcodeToString maps Rcodes to strings.
var RcodeToString = map[uint16]string{
	RcodeSuccess:                "NOERROR",
	RcodeFormatError:            "FORMERR",
	RcodeServerFailure:          "SERVFAIL",
	RcodeNameError:              "NXDOMAIN",
	RcodeNotImplemented:         "NOTIMPL",
	RcodeRefused:                "REFUSED",
	RcodeYXDomain:               "YXDOMAIN", // See RFC 2136.
	RcodeYXRrset:                "YXRRSET",
	RcodeNXRrset:                "NXRRSET",
	RcodeNotAuth:                "NOTAUTH",
	RcodeNotZone:                "NOTZONE",
	RcodeBadSig:                 "BADSIG", // Also known as RcodeBadVers "BADVERS", see RFC 6891.
	RcodeStatefulNotImplemented: "DSOTYPENI",
	RcodeBadKey:                 "BADKEY",
	RcodeBadTime:                "BADTIME",
	RcodeBadMode:                "BADMODE",
	RcodeBadName:                "BADNAME",
	RcodeBadAlg:                 "BADALG",
	RcodeBadTrunc:               "BADTRUNC",
	RcodeBadCookie:              "BADCOOKIE",
}

// Domain names are a sequence of counted strings split at the dots. They end with a zero-length string.

// packName packs a domain name. Why should this be exported?
func packName(s string, msg []byte, off int, compression map[string]uint16, compress bool) (off1 int, err error) {
	// XXX: A logical copy of this function exists in IsDomainName and
	// should be kept in sync with this function.

	// If not fully qualified, error out.
	if !dnsutilIsFqdn(s) {
		return len(msg), ErrFqdn
	}

	ls := len(s)

	// Each dot ends a segment of the name.
	// We trade each dot byte for a length byte.
	// Except for escaped dots (\.), which are normal dots.
	// There is also a trailing zero.

	// Compression
	pointer := ^uint16(0)

	// Emit sequence of counted strings, chopping at dots.
	var (
		begin     int
		compBegin int
		compOff   int
		bs        []byte
		wasDot    bool
	)
loop:
	for i := 0; i < ls; i++ {
		var c byte
		if bs == nil {
			c = s[i]
		} else {
			c = bs[i]
		}

		switch c {
		case '\\':
			if off+1 > len(msg) {
				return len(msg), ErrBuf
			}

			if bs == nil {
				bs = []byte(s)
			}

			// check for \DDD
			if ddd.Is(bs[i+1:]) {
				bs[i] = ddd.ToByte(bs[i+1:])
				copy(bs[i+1:ls-3], bs[i+4:])
				ls -= 3
				compOff += 3
			} else {
				copy(bs[i:ls-1], bs[i+1:])
				ls--
				compOff++
			}

			wasDot = false
		case '.':
			if i == 0 && len(s) > 1 {
				// leading dots are not legal except for the root zone
				return len(msg), ErrName
			}

			if wasDot {
				// two dots back to back is not legal
				return len(msg), ErrName
			}
			wasDot = true

			labelLen := i - begin
			if labelLen >= 1<<6 { // top two bits of length must be clear
				return len(msg), ErrLabel
			}

			// off can already (we're in a loop) be bigger than len(msg)
			// this happens when a name isn't fully qualified
			if off+1+labelLen > len(msg) {
				return len(msg), ErrBuf
			}

			// Don't try to compress '.'
			// We should only compress when compress is true, but we should also still pick
			// up names that can be used for *future* compression(s).
			if !isRootLabel(s, bs, begin, ls) && compression != nil {
				if p, ok := compression[s[compBegin:]]; ok {
					// The first hit is the longest matching dname
					// keep the pointer offset we get back and store
					// the offset of the current name, because that's
					// where we need to insert the pointer later

					// If compress is true, we're allowed to compress this dname
					if compress {
						pointer = p // Where to point to
						break loop
					}
				} else if off < maxCompressionOffset {
					// Only offsets smaller than maxCompressionOffset can be used.
					compression[s[compBegin:]] = uint16(off)
				}
			}

			// The following is covered by the length check above.
			msg[off] = byte(labelLen)

			if bs == nil {
				copy(msg[off+1:], s[begin:i])
			} else {
				copy(msg[off+1:], bs[begin:i])
			}
			off += 1 + labelLen

			begin = i + 1
			compBegin = begin + compOff
		default:
			wasDot = false
		}
	}

	// Root label is special
	if isRootLabel(s, bs, 0, ls) {
		return off, nil
	}

	// If we did compression and we find something add the pointer here
	if pointer != ^uint16(0) {
		// We have two bytes (14 bits) to put the pointer in
		binary.BigEndian.PutUint16(msg[off:], 0xC000|pointer)
		return off + 2, nil
	}

	if off < len(msg) {
		msg[off] = 0
	}

	return off + 1, nil
}

// isRootLabel returns whether s or bs, from off to end, is the root
// label ".".
//
// If bs is nil, s will be checked, otherwise bs will be checked.
func isRootLabel(s string, bs []byte, off, end int) bool {
	if bs == nil {
		return s[off:end] == "."
	}

	return end-off == 1 && bs[off] == '.'
}

// Unpack a domain name. WHY exported??
// In addition to the simple sequences of counted strings above, domain names are allowed to refer to strings elsewhere in the
// packet, to avoid repeating common suffixes when returning many entries in a single domain. The pointers are marked
// by a length byte with the top two bits set. Ignoring those two bits, that byte and the next give a 14 bit offset from into msg
// where we should pick up the trail.
// Note that if we jump elsewhere in the packet, we record the last offset we read from when we found the first pointer,
// which is where the next record or record field will start. We enforce that pointers always point backwards into the message.

// UnpackName unpacks a domain name into a string. It returns the name, the new offset into msg and any error that occurred.
// When an error is encountered, the unpacked name will be discarded and len(msg) will be returned as the offset.
func UnpackName(msg []byte, off int) (string, int, error) {
	s := cryptobyte.String(msg[off:])
	name, err := unpackName(&s, msg)
	if err != nil {
		return "", len(msg), err
	}
	return name, offset(s, msg), nil
}

func unpackName(s *cryptobyte.String, msgBuf []byte) (string, error) {
	name := make([]byte, 0, maxDomainNamePresentationLength) // should we make the cap smaller, and then pay the price for larger names?
	budget := maxDomainNameWireOctets
	var ptrs bool

	// If we never see a pointer, we need to ensure that we advance s to our final position.
	cs := *s

	for {
		var c byte
		if !cs.ReadUint8(&c) {
			return "", ErrUnpackOverflow
		}
		switch c & 0xC0 {
		case 0x00: // literal string
			var label []byte
			if !cs.ReadBytes(&label, int(c)) {
				return "", ErrUnpackOverflow
			}
			// If we see a zero-length label (root label), this is the end of the name.
			if len(label) == 0 {
				if !ptrs {
					*s = cs
				}
				if len(name) == 0 {
					return ".", nil
				}
				return string(name), nil
			}
			if budget -= len(label) + 1; budget <= 0 { // +1 for the label separator
				return "", ErrLongDomain
			}
			for _, b := range label {
				if isLabelSpecial(b) {
					name = append(name, '\\', b)
				} else if b < ' ' || b > '~' {
					name = append(name, ddd.Escape(b)...)
				} else {
					name = append(name, b)
				}
			}
			name = append(name, '.')
		case 0xC0: // pointer
			var c1 byte
			if !cs.ReadUint8(&c1) {
				return "", ErrUnpackOverflow
			}
			// If this is the first pointer we've seen, we need to advance s to our current position.
			if !ptrs {
				*s = cs
			}
			// The pointer should always point backwards to an earlier part of the message. Technically it could work pointing
			// forwards, but we choose not to support that as RFC 1035 specifically refers to a "prior
			// occurrence".
			off := uint16(c&^0xC0)<<8 | uint16(c1)
			if int(off) >= offset(cs, msgBuf)-2 {
				return "", &Error{err: "pointer not to prior occurrence of name"}
			}
			// Jump to the offset in msgBuf. We carry msgBuf around with us solely for this line.
			cs = msgBuf[off:]
			ptrs = true
		default: // 0x80 and 0x40 are reserved
			return "", &Error{err: "reserved domain name label type"}
		}
	}
}

// packQuestion packs an RR into a question section.
func packQuestion(rr RR, msg []byte, off int) (off1 int, err error) {
	if rr == nil {
		return len(msg), &Error{err: "nil rr"}
	}

	off, err = packName(rr.Header().Name, msg, off, nil, false)
	if err != nil {
		return len(msg), err
	}
	rrtype := RRToType(rr)
	off, err = pack.Uint16(rrtype, msg, off)
	if err != nil {
		return len(msg), err
	}

	off, err = pack.Uint16(rr.Header().Class, msg, off)
	if err != nil {
		return len(msg), err
	}
	return off, nil
}

// PackRR packs a resource record rr into msg[off:].
// See PackName for documentation about the compression.
func PackRR(rr RR, msg []byte, off int, compression map[string]uint16) (off1 int, err error) {
	_, off1, err = packRR(rr, msg, off, compression)
	return off1, err
}

func packRR(rr RR, msg []byte, off int, compression map[string]uint16) (headerEnd int, off1 int, err error) {
	if rr == nil {
		return len(msg), len(msg), &Error{err: "nil rr"}
	}

	rrtype := RRToType(rr)
	headerEnd, err = rr.Header().packHeader(msg, off, rrtype, compression)
	if err != nil {
		return headerEnd, len(msg), err
	}
	off1, err = zpack(rr, msg, headerEnd, compression)
	if err != nil {
		return headerEnd, len(msg), err
	}

	rdlength := off1 - headerEnd
	if int(uint16(rdlength)) != rdlength { // overflow
		return headerEnd, len(msg), ErrLenData
	}

	// The RDLENGTH field is the last field in the header and we set it here.
	binary.BigEndian.PutUint16(msg[headerEnd-2:], uint16(rdlength))
	return headerEnd, off1, nil
}

// UnpackRR unpacks msg[off:] into an RR.
func UnpackRR(msg []byte, off int) (rr RR, off1 int, err error) {
	if off < 0 || off >= len(msg) {
		return nil, off, &Error{err: "bad offset"}
	}
	s := cryptobyte.String(msg[off:])
	rr, err = unpackRR(&s, msg)
	return rr, offset(s, msg), err
}

func unpackRR(msg *cryptobyte.String, msgBuf []byte) (RR, error) {
	h, rdlength, err := unpackRRHeader(msg, msgBuf)
	if err != nil {
		return nil, err
	}
	return unpackRRWithHeader(h, rdlength, msg, msgBuf)
}

func unpackRRWithHeader(h Header, rdlength uint16, msg *cryptobyte.String, msgBuf []byte) (RR, error) {
	var data []byte
	if !msg.ReadBytes(&data, int(rdlength)) {
		h := h // Avoid spilling h to the heap in the happy path.
		return &h, ErrTruncatedMessage
	}

	// Restrict msgBuf to the end of the RR (the current position of msg) so
	// that we compute the correct offset in unpackName.
	msgBuf = msgBuf[:offset(*msg, msgBuf)]

	var rr RR
	// TODO(miek): custom RR types here?? You can just add to the map? document and test.
	if newFn, ok := TypeToRR[h.t]; ok {
		rr = newFn()
		*rr.Header() = h
	} else {
		rr = &RFC3597{Hdr: h}
	}

	if len(data) == 0 {
		return rr, nil
	}

	if err := zunpack(rr, data, msgBuf); err != nil {
		return rr, err
	}

	return rr, nil
}

// Pack packs a Msg: it is converted to to wire format.
func (m *Msg) Pack() error {
	if m.isCompressible() {
		compressions := make(map[string]uint16) // Compression pointer mappings.
		return m.pack(compressions)
	}
	return m.pack(nil)
}

func (m *Msg) pack(compression map[string]uint16) (err error) {
	if m.Rcode < 0 || m.Rcode > 0xFFF {
		return ErrRcode
	}

	// Convert convenient Msg into wire-like Header.
	var dh header
	dh.ID = m.ID
	dh.Bits = uint16(m.Opcode)<<11 | uint16(m.Rcode&0xF)
	if m.Response {
		dh.Bits |= _QR
	}
	if m.Authoritative {
		dh.Bits |= _AA
	}
	if m.Truncated {
		dh.Bits |= _TC
	}
	if m.RecursionDesired {
		dh.Bits |= _RD
	}
	if m.RecursionAvailable {
		dh.Bits |= _RA
	}
	if m.Zero {
		dh.Bits |= _Z
	}
	if m.AuthenticatedData {
		dh.Bits |= _AD
	}
	if m.CheckingDisabled {
		dh.Bits |= _CD
	}

	dh.Qdcount = uint16(len(m.Question))
	dh.Ancount = uint16(len(m.Answer))
	dh.Nscount = uint16(len(m.Ns))
	dh.Arcount = uint16(len(m.Extra) + m.isPseudo())

	// We need the uncompressed length here, because we first pack it and then compress it.
	l := m.Len()
	if len(m.Data) < l {
		m.Data = append(m.Data, make([]byte, l-len(m.Data))...)
	}

	// Pack it in: header and then the pieces.
	off := 0
	if off, err = dh.pack(m.Data, off); err != nil {
		return err
	}
	for _, r := range m.Question {
		if off, err = packQuestion(r, m.Data, off); err != nil {
			return err
		}
		break
	}
	for _, r := range m.Answer {
		if _, off, err = packRR(r, m.Data, off, compression); err != nil {
			return err
		}
	}
	for _, r := range m.Ns {
		if _, off, err = packRR(r, m.Data, off, compression); err != nil {
			return err
		}
	}

	// Add an OPT RR if we see any of these.
	if m.isPseudo() > 0 {
		opt := &OPT{} // hack, empty name, that gets filled if we did something
		if m.UDPSize > MinMsgSize {
			opt.Hdr.Name = "."
			opt.SetUDPSize(m.UDPSize)
		}
		if m.Rcode > 0xF {
			opt.Hdr.Name = "."
			opt.SetRcode(m.Rcode) // we leave m.Rcode as packing/unpacking will set the correct bits there.
		}
		if m.Security {
			opt.Hdr.Name = "."
			opt.SetSecurity(true)
		}
		if m.CompactAnswers {
			opt.Hdr.Name = "."
			opt.SetCompactAnswers(true)
		}
		for _, option := range m.Pseudo {
			if edns0, ok := option.(EDNS0); ok {
				opt.Hdr.Name = "."
				opt.Options = append(opt.Options, edns0)
			}
		}
		// Only pack opt if something has been put into it, otherwise we may a TSIG/SIG0.
		// Pack it here so we don't added it the m.Extra, as the options (only) should be available in pseudo.
		// Also OPT may be anywhere in m.Extra, here it will be first.
		if opt.Hdr.Name == "." {
			if _, off, err = packRR(opt, m.Data, off, nil); err != nil {
				return err
			}
		}
	}
	m.ps = 0

	for _, r := range m.Extra {
		if _, off, err = packRR(r, m.Data, off, compression); err != nil {
			return err
		}
	}

	// records that really need to be last, TSIG or SGI0
	for _, r := range m.Pseudo {
		if _, ok := r.(*TSIG); ok {
			if _, off, err = packRR(r, m.Data, off, compression); err != nil {
				return err
			}
			m.ps++
		}
		if _, ok := r.(*SIG); ok {
			if _, off, err = packRR(r, m.Data, off, compression); err != nil {
				return err
			}
			m.ps++
		}
	}

	m.Data = m.Data[:off]
	return nil
}

// We only allow a single question in the question section.
func (m *Msg) unpackQuestion(msg *cryptobyte.String, msgBuf []byte) (RR, error) {
	name, err := unpackName(msg, msgBuf)
	if err != nil {
		return nil, fmt.Errorf("%s: question.Name", err.Error())
	}
	var qtype uint16
	if !msg.Empty() && !msg.ReadUint16(&qtype) {
		return nil, ErrTruncatedMessage.Fmt(": %s", "question.Type")
	}
	m.qtype = qtype

	var qclass uint16
	if !msg.Empty() && !msg.ReadUint16(&qclass) {
		return nil, ErrTruncatedMessage.Fmt(": %s", "question.Class")
	}

	var rr RR
	if newFn, ok := TypeToRR[qtype]; ok {
		rr = newFn()
		*rr.Header() = Header{Name: name, t: qtype, Class: qclass}
	} else {
		rr = &RFC3597{Hdr: Header{Name: name, t: qtype, Class: qclass}}
	}
	return rr, nil
}

func (m *Msg) unpackQuestions(cnt uint16, msg *cryptobyte.String, msgBuf []byte) ([]RR, error) {
	// We don't preallocate dst according to cnt as that value may be attacker
	// controlled. A malicious adversary could send us as 12-byte packet
	// containing only the header that claims to contain 65535 questions. As
	// Question takes 24-bytes, we'd end up allocating more than 1.5MiB from a
	// mere 12-byte packet.
	var dst []RR
	for i := 0; i < int(cnt); i++ {
		r, err := m.unpackQuestion(msg, msgBuf)
		if err != nil {
			return dst, err
		}
		dst = append(dst, r)
	}
	return dst, nil
}

func unpackRRs(cnt uint16, msg *cryptobyte.String, msgBuf []byte) ([]RR, error) {
	// See unpackQuestions for why we don't pre-allocate here.
	//
	// In the additional section we stop unpacking when we see
	var dst []RR
	for i := 0; i < int(cnt); i++ {
		r, err := unpackRR(msg, msgBuf)
		if err != nil {
			return dst, err
		}
		dst = append(dst, r)
	}
	return dst, nil
}

func (m *Msg) unpack(dh header, msg, msgBuf []byte) error {
	s := cryptobyte.String(msg)
	var err error
	m.Question, err = m.unpackQuestions(dh.Qdcount, &s, msgBuf)
	if err != nil {
		return err
	}
	if m.Options&OptionUnpackQuestion == OptionUnpackQuestion {
		return nil
	}

	m.Answer, err = unpackRRs(dh.Ancount, &s, msgBuf)
	if err != nil {
		return err
	}

	m.Ns, err = unpackRRs(dh.Nscount, &s, msgBuf)
	if err != nil {
		return err
	}

	m.Extra, err = unpackRRs(dh.Arcount, &s, msgBuf)
	if err != nil {
		return err
	}

	// Check for the OPT RR and remove it entirely, unpack the OPT for option codes and put those in the Pseudo
	// section. Any TSIG and SIG0 records will also be put in the pseudo section, but after the options.

	j := 0
	for i := 0; i < len(m.Extra)-j; i++ {
		rr := m.Extra[i]
		if opt, ok := rr.(*OPT); ok {
			// move to end, so it can be removed later and unpack the opt for the settings.
			m.Security = opt.Security()
			m.CompactAnswers = opt.CompactAnswers()
			m.Rcode += opt.Rcode() // See TestMsgExtendedRcode.
			m.Version = opt.Version()
			m.UDPSize = opt.UDPSize()

			m.Pseudo = make([]RR, len(opt.Options))
			for i, o := range opt.Options {
				m.Pseudo[i] = RR(o)
			}

			m.Extra[len(m.Extra)-j-1] = rr
			j++
		}
	}
	// remove the OPT RR
	m.Extra = m.Extra[:len(m.Extra)-j]
	m.ps = 0

	for _, r := range m.Extra {
		if _, ok := r.(*TSIG); ok {
			m.ps++
		}
		if _, ok := r.(*SIG); ok {
			m.ps++
		}
	}

	if !s.Empty() {
		return &Error{err: "trailing message data"}
	}
	return nil
}

// Unpack unpacks a binary message that sits in m.Data to a Msg structure.
func (m *Msg) Unpack() error {
	s := cryptobyte.String(m.Data)
	var dh header
	if !dh.unpack(&s) {
		return ErrUnpackOverflow.Fmt(": %s", "MsgHeader")
	}
	m.setMsgHeader(dh)
	if m.Options&OptionUnpackHeader == OptionUnpackHeader {
		if m.Options&OptionUnpackQuestion != OptionUnpackQuestion {
			return nil
		}
	}
	return m.unpack(dh, s, m.Data)
}

// Convert a complete message to a string with dig-like output.
func (m *Msg) String() string {
	if m == nil {
		return "<nil> Msg"
	}
	sb := strings.Builder{}

	sb.WriteString(m.MsgHeader.String())
	// if core EDNS flags are set, we print this (flags are already handles in MsgHeader
	if m.UDPSize > 0 || m.Security || m.CompactAnswers {
		sb.WriteString(";; EDNS, version: ")
		sb.WriteString(strconv.Itoa(int(m.Version)))
		sb.WriteString(", udp: ")
		sb.WriteString(strconv.Itoa(int(m.UDPSize)))
		sb.WriteByte('\n')
	}

	sections := [5]string{"QUESTION", "PSEUDO", "ANSWER", "AUTHORITY", "ADDITIONAL"}
	if m.MsgHeader.Opcode == OpcodeUpdate {
		sections = [5]string{"ZONE", "PSEUDO", "PREREQ", "UPDATE", "ADDITIONAL"}
	}
	sb.WriteString(";; ")
	sb.WriteString(sections[0])
	sb.WriteString(": ")
	sb.WriteString(strconv.Itoa(len(m.Question)))
	sb.WriteString(", ")

	sb.WriteString(sections[1])
	sb.WriteString(": ")
	sb.WriteString(strconv.Itoa(len(m.Pseudo)))
	sb.WriteString(", ")

	sb.WriteString(sections[2])
	sb.WriteString(": ")
	sb.WriteString(strconv.Itoa(len(m.Answer)))
	sb.WriteString(", ")

	sb.WriteString(sections[3])
	sb.WriteString(": ")
	sb.WriteString(strconv.Itoa(len(m.Ns)))
	sb.WriteString(", ")

	sb.WriteString(sections[4])
	sb.WriteString(": ")
	sb.WriteString(strconv.Itoa(len(m.Extra)))
	sb.WriteByte('\n')

	if len(m.Question) > 0 {
		sb.WriteString("\n;; ")
		sb.WriteString(sections[0])
		sb.WriteString(" SECTION:\n")
		for _, r := range m.Question {
			// as we fake RRs to be present in the question section, just manual unpack print the header without the TTL here.
			sb.WriteString(r.Header().Name)
			sb.WriteByte('\t')
			sb.WriteByte('\t')
			sb.WriteString(sprintClass(r.Header().Class))
			sb.WriteByte('\t')
			rrtype := r.Header().t
			if rrtype == 0 {
				rrtype = RRToType(r)
			}
			sb.WriteString(sprintType(rrtype))
			sb.WriteByte('\n')
		}
	}
	if len(m.Pseudo) > 0 {
		sb.WriteString("\n;; ")
		sb.WriteString(sections[1])
		sb.WriteString(" SECTION:\n")
		for _, r := range m.Pseudo {
			sb.WriteString(r.String())
			sb.WriteByte('\n')
		}
	}
	if len(m.Answer) > 0 {
		sb.WriteString("\n;; ")
		sb.WriteString(sections[2])
		sb.WriteString(" SECTION:\n")
		for _, r := range m.Answer {
			sb.WriteString(r.String())
			sb.WriteByte('\n')
		}
	}
	if len(m.Ns) > 0 {
		sb.WriteString("\n;; ")
		sb.WriteString(sections[2])
		sb.WriteString(" SECTION:\n")
		for _, r := range m.Ns {
			sb.WriteString(r.String())
			sb.WriteByte('\n')
		}
	}
	if len(m.Extra) > 0 {
		sb.WriteString("\n;; ")
		sb.WriteString(sections[3])
		sb.WriteString(" SECTION:\n")
		for _, r := range m.Extra {
			sb.WriteString(r.String())
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

// isCompressible returns whether the msg may be compressible.
func (m *Msg) isCompressible() bool {
	// If we only have one question, there is nothing we can ever compress.
	return len(m.Question) > 1 || len(m.Answer) > 0 ||
		len(m.Ns) > 0 || len(m.Extra) > 0
}

// isPseudo returns (1) true of we should have a pseudo section in this message, or not (0). It returns an
// int becuse we need that number of the Extra section sizing.
func (m *Msg) isPseudo() int {
	if len(m.Pseudo) > 0 || m.UDPSize > MinMsgSize || m.Security || m.CompactAnswers || m.Rcode > 0xF {
		return 1
	}
	return 0
}

// Len returns the message length when in uncompressed wire format.
func (m *Msg) Len() int {
	l := MsgHeaderSize

	for _, r := range m.Question {
		l += r.Len()
	}
	for _, r := range m.Answer {
		l += r.Len()
	}
	for _, r := range m.Ns {
		l += r.Len()
	}
	for _, r := range m.Extra {
		l += r.Len()
	}

	for _, r := range m.Pseudo {
		l += r.Len()
	}

	const minHeaderSize = 11 // smallest possible RR header where the name is the root label.

	if m.isPseudo() > 0 {
		// If we find things in pseudo we get an OPT RR (fix length) plus the length of the option. OPT is always 11, 10 + "." (root label)
		l += minHeaderSize
	}

	if l > MaxMsgSize {
		return MaxMsgSize
	}

	return l
}

func (dh *header) pack(msg []byte, off int) (int, error) {
	off, err := pack.Uint16(dh.ID, msg, off)
	if err != nil {
		return off, (&Error{err: err.Error()}).Fmt(": %s", "header.ID")
	}
	off, err = pack.Uint16(dh.Bits, msg, off)
	if err != nil {
		return off, (&Error{err: err.Error()}).Fmt(": %s", "header.Bits")
	}
	off, err = pack.Uint16(dh.Qdcount, msg, off)
	if err != nil {
		return off, (&Error{err: err.Error()}).Fmt(": %s", "header.Qdcount")
	}
	off, err = pack.Uint16(dh.Ancount, msg, off)
	if err != nil {
		return off, (&Error{err: err.Error()}).Fmt(": %s", "header.Ancount")
	}
	off, err = pack.Uint16(dh.Nscount, msg, off)
	if err != nil {
		return off, (&Error{err: err.Error()}).Fmt(": %s", "header.Nscount")
	}
	off, err = pack.Uint16(dh.Arcount, msg, off)
	if err != nil {
		return off, (&Error{err: err.Error()}).Fmt(": %s", "header.Arcount")
	}
	return off, nil
}

func (dh *header) unpack(msg *cryptobyte.String) bool {
	return msg.ReadUint16(&dh.ID) &&
		msg.ReadUint16(&dh.Bits) &&
		msg.ReadUint16(&dh.Qdcount) &&
		msg.ReadUint16(&dh.Ancount) &&
		msg.ReadUint16(&dh.Nscount) &&
		msg.ReadUint16(&dh.Arcount)
}

// setHdr set the header in the dns using the binary data in dh.
func (m *Msg) setMsgHeader(dh header) {
	m.ID = dh.ID
	m.Response = dh.Bits&_QR != 0
	m.Opcode = uint8(dh.Bits>>11) & 0xF
	m.Authoritative = dh.Bits&_AA != 0
	m.Truncated = dh.Bits&_TC != 0
	m.RecursionDesired = dh.Bits&_RD != 0
	m.RecursionAvailable = dh.Bits&_RA != 0
	m.Zero = dh.Bits&_Z != 0 // _Z covers the zero bit, which should be zero; not sure why we set it to the opposite.
	m.AuthenticatedData = dh.Bits&_AD != 0
	m.CheckingDisabled = dh.Bits&_CD != 0
	m.Rcode = dh.Bits & 0xF
}

// io.Reader and io.Writer interfaces implementation.

// Write writes the buffer p to the m.Data.
func (m *Msg) Write(p []byte) (n int, err error) {
	if len(m.Data) == 0 {
		if err := m.Pack(); err != nil {
			return 0, err
		}
	}

	n = copy(m.Data, p)
	return n, nil
}

// Read reads the data from m.Data into p.
func (m *Msg) Read(p []byte) (n int, err error) {
	if len(m.Data) == 0 {
		if err := m.Pack(); err != nil {
			return 0, err
		}
	}

	n = copy(p, m.Data)
	return n, nil
}

// WriteTo writes the message to w. W must be a [ResponseWriter], when w contains a *net.TCPConn, the write is prefixed with an uint16 with the
// length of the buffer, otherwise the m.Data is written as-is. If w is a [ResponseController] a write timeout
// is applied. If W is also a [ResponseController] write timeouts are applied.
func (m *Msg) WriteTo(w io.Writer) (int64, error) {
	r, ok := w.(ResponseWriter)
	if !ok {
		return 0, fmt.Errorf("dns: writer is not a ResponseWriter")
	}

	if len(m.Data) == 0 {
		if err := m.Pack(); err != nil {
			return 0, err
		}
	}

	if rc, ok := w.(ResponseController); ok {
		rc.SetWriteDeadline()
	}

	if sock, ok := r.Conn().(*net.UDPConn); ok {
		sess := r.Session()
		if sess != nil {
			oob := sourceFromOOB(sess.oobdata)
			n, _, err := sock.WriteMsgUDP(m.Data, oob, sess.raddr)
			return int64(n), err
		}

		n, err := r.Conn().Write(m.Data)
		return int64(n), err
	}

	l := make([]byte, 2, 2)
	binary.BigEndian.PutUint16(l, uint16(len(m.Data)))
	l = append(l, m.Data...)
	n, err := r.Write(l)
	return int64(n), err
}

// ReadFrom reads from r. When r is a *net.TCPConn, first 2 bytes of length are read, then m.Data is *resized*
// to this length and the data is read. Otherwise the data is read into m.Data. It is expected any deadlines
// are set if there is an underlying socket. No read timeouts are applied.
func (m *Msg) ReadFrom(r io.Reader) (int64, error) {
	if len(m.Data) == 0 {
		if err := m.Pack(); err != nil {
			return 0, err
		}
	}

	if sock, ok := r.(*net.UDPConn); ok {
		n, err := sock.Read(m.Data)
		if err != nil {
			return 0, err
		}
		m.Data = m.Data[:n]
		return int64(n), nil
	}

	// When doing io.Copy that underlaying type we get from net is net.tcpConnWithoutWriteTo, not a
	// net.TCPConn.For udp this seems not to be the case, so the fallthrough when things are not UDP like
	// is too assume TCP.

	l := uint16(0)
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return 0, err
	}
	li := int(l)
	if li < MsgHeaderSize {
		return 0, fmt.Errorf("dns: TCP message size %d, can not be smaller than %d", li, MsgHeaderSize)
	}

	if len(m.Data) < li {
		m.Data = append(m.Data, make([]byte, li-len(m.Data))...)
	} else {
		m.Data = m.Data[:li]
	}
	n, err := io.ReadFull(r, m.Data)
	if err != nil {
		m.Data = m.Data[:n]
	}
	return int64(n), err
}
