package dns

import (
	"encoding/binary"
	"strconv"
	"strings"
	"time"
)

// HMAC hashing codes. These are transmitted as domain names.
const (
	HmacSHA1   = "hmac-sha1."
	HmacSHA224 = "hmac-sha224."
	HmacSHA256 = "hmac-sha256."
	HmacSHA384 = "hmac-sha384."
	HmacSHA512 = "hmac-sha512."

	HmacMD5 = "hmac-md5.sig-alg.reg.int." // Deprecated: HmacMD5 is no longer supported.
)

// TSIG is the RR the holds the transaction signature of a message. See RFC 2845 and RFC 4635.
type TSIG struct {
	Hdr        Header
	Algorithm  string `dns:"domain-name"`
	TimeSigned uint64 `dns:"uint48"`
	Fudge      uint16
	MACSize    uint16
	MAC        string `dns:"size-hex:MACSize"`
	OrigID     uint16
	Error      uint16
	OtherLen   uint16
	OtherData  string `dns:"size-hex:OtherLen"`
}

func (rr *TSIG) Header() *Header { return &rr.Hdr }
func (rr *TSIG) Len() int {
	return rr.Hdr.Len() + len(rr.Algorithm) + 8 + int(rr.MACSize) + 6 + int(rr.OtherLen)
}

func (rr *TSIG) Data() []Field {
	return []Field{rr.Algorithm, rr.TimeSigned, rr.Fudge, rr.MACSize, rr.MAC, rr.OrigID, rr.Error, rr.OtherLen, rr.OtherData}
}

func (rr *TSIG) String() string {
	sb := sprintHeader(rr)
	sprintData(sb, rr.Algorithm, tsigTimeToString(rr.TimeSigned),
		strconv.Itoa(int(rr.Fudge)), strconv.Itoa(int(rr.MACSize)),
		strings.ToUpper(rr.MAC), strconv.Itoa(int(rr.OrigID)),
		strconv.Itoa(int(rr.Error)), strconv.Itoa(int(rr.OtherLen)), rr.OtherData)
	return sb.String()
}

func (*TSIG) parse(c *zlexer, origin string) *ParseError {
	return &ParseError{err: "TSIG records do not have a presentation format"}
}

// Translate the TSIG time signed into a date. There is no need for RFC1982 calculations as this date is 48 bits.
func tsigTimeToString(t uint64) string {
	ti := time.Unix(int64(t), 0).UTC()
	return ti.Format("20060102150405")
}

func (rr *TSIG) Sign(k TSIGSigner, m *Msg, options TSIGOption) error {
	// MESSAGE ID??
	if err := k.Sign(rr, m); err != nil {
		return err
	}
	// restore msg ID, as the origID is used to calculate hash
	defer func() {
		binary.BigEndian.PutUint16(m.Data[0:2], m.ID)
	}()
	rr.MACSize = uint16(len(rr.MAC) / 2)
	rr.TimeSigned = 0
	// bla bla
	return nil
}

func (rr *TSIG) Verify(k TSIGVerifier, m *Msg, options TSIGOption) error {
	return nil
}

type TSIGOption struct {
	TimersOnly bool
	RequestMAC string
}

type (
	TSIGSigner interface {
		// Sign is passed the DNS message (that does not yet have a TSIG attached) to be signed and a partial TSIG RR. It returns the signature in
		// t.MAC as a hex encoded string.
		Sign(t *TSIG, m *Msg) error
	}

	TSIGVerifier interface {
		// Verify is passed the full DNS message to be verified and the TSIG RR. If the signature is valid it will return nil, otherwise an error.
		Verify(t *TSIG, m *Msg, options TSIGOption) error
	}
)

/*
// TsigProvider provides the API to plug-in a custom TSIG implementation.
type TsigProvider interface {
	// Generate is passed the DNS message to be signed and the partial TSIG RR. It returns the signature and nil, otherwise an error.
	Generate(msg []byte, t *TSIG) ([]byte, error)
	// Verify is passed the DNS message to be verified and the TSIG RR. If the signature is valid it will return nil, otherwise an error.
	Verify(msg []byte, t *TSIG) error
}
func (key tsigHMACProvider) Verify(msg []byte, t *TSIG) error {
	b, err := key.Generate(msg, t)
	if err != nil {
		return err
	}
	mac, err := hex.DecodeString(t.MAC)
	if err != nil {
		return err
	}
	if !hmac.Equal(b, mac) {
		return ErrSig
	}
	return nil
}

type tsigSecretProvider map[string]string

func (ts tsigSecretProvider) Generate(msg []byte, t *TSIG) ([]byte, error) {
	key, ok := ts[t.Hdr.Name]
	if !ok {
		return nil, ErrSecret
	}
	return tsigHMACProvider(key).Generate(msg, t)
}

func (ts tsigSecretProvider) Verify(msg []byte, t *TSIG) error {
	key, ok := ts[t.Hdr.Name]
	if !ok {
		return ErrSecret
	}
	return tsigHMACProvider(key).Verify(msg, t)
}

// If we have the MAC use this type to convert it to wiredata. Section 3.4.3. Request MAC
type macWireFmt struct {
	MACSize uint16
	MAC     string `dns:"size-hex:MACSize"`
}

// 3.3. Time values used in TSIG calculations
type timerWireFmt struct {
	TimeSigned uint64 `dns:"uint48"`
	Fudge      uint16
}

// TsigGenerate fills out the TSIG record attached to the message.
// The message should contain a "stub" TSIG RR with the algorithm, key name
// (owner name of the RR), time fudge (defaults to 300 seconds) and the current
// time The TSIG MAC is saved in that Tsig RR. When TsigGenerate is called for
// the first time requestMAC should be set to the empty string and timersOnly to
// false.
func TsigGenerate(m *Msg, secret, requestMAC string, timersOnly bool) ([]byte, string, error) {
	return TsigGenerateWithProvider(m, tsigHMACProvider(secret), requestMAC, timersOnly)
}

// TsigGenerateWithProvider is similar to TsigGenerate, but allows for a custom TsigProvider.
func TsigGenerateWithProvider(m *Msg, provider TsigProvider, requestMAC string, timersOnly bool) ([]byte, string, error) {
	if m.IsTsig() == nil {
		panic("dns: TSIG not last RR in additional")
	}

	rr := m.Extra[len(m.Extra)-1].(*TSIG)
	m.Extra = m.Extra[0 : len(m.Extra)-1] // kill the TSIG from the msg
	mbuf, err := m.Pack()
	if err != nil {
		return nil, "", err
	}

	buf, err := tsigBuffer(mbuf, rr, requestMAC, timersOnly)
	if err != nil {
		return nil, "", err
	}

	t := new(TSIG)
	// Copy all TSIG fields except MAC, its size, and time signed which are filled when signing.
	*t = *rr
	t.TimeSigned = 0
	t.MAC = ""
	t.MACSize = 0

	// Sign unless there is a key or MAC validation error (RFC 8945 5.3.2)
	if rr.Error != RcodeBadKey && rr.Error != RcodeBadSig {
		mac, err := provider.Generate(buf, rr)
		if err != nil {
			return nil, "", err
		}
		t.TimeSigned = rr.TimeSigned
		t.MAC = hex.EncodeToString(mac)
		t.MACSize = uint16(len(t.MAC) / 2) // Size is half!
	}

	tbuf := make([]byte, Len(t))
	off, err := PackRR(t, tbuf, 0, nil, false)
	if err != nil {
		return nil, "", err
	}
	mbuf = append(mbuf, tbuf[:off]...)
	// Update the ArCount directly in the buffer.
	binary.BigEndian.PutUint16(mbuf[10:], uint16(len(m.Extra)+1))

	return mbuf, t.MAC, nil
}

// TsigVerify verifies the TSIG on a message. If the signature does not
// validate the returned error contains the cause. If the signature is OK, the
// error is nil.
func TsigVerify(msg []byte, secret, requestMAC string, timersOnly bool) error {
	return tsigVerify(msg, tsigHMACProvider(secret), requestMAC, timersOnly, uint64(time.Now().Unix()))
}

// TsigVerifyWithProvider is similar to TsigVerify, but allows for a custom TsigProvider.
func TsigVerifyWithProvider(msg []byte, provider TsigProvider, requestMAC string, timersOnly bool) error {
	return tsigVerify(msg, provider, requestMAC, timersOnly, uint64(time.Now().Unix()))
}

// actual implementation of TsigVerify, taking the current time ('now') as a parameter for the convenience of tests.
func tsigVerify(msg []byte, provider TsigProvider, requestMAC string, timersOnly bool, now uint64) error {
	// Strip the TSIG from the incoming msg
	stripped, tsig, err := stripTsig(msg)
	if err != nil {
		return err
	}

	buf, err := tsigBuffer(stripped, tsig, requestMAC, timersOnly)
	if err != nil {
		return err
	}

	if err := provider.Verify(buf, tsig); err != nil {
		return err
	}

	// Fudge factor works both ways. A message can arrive before it was signed because
	// of clock skew.
	// We check this after verifying the signature, following draft-ietf-dnsop-rfc2845bis
	// instead of RFC2845, in order to prevent a security vulnerability as reported in CVE-2017-3142/3143.
	ti := now - tsig.TimeSigned
	if now < tsig.TimeSigned {
		ti = tsig.TimeSigned - now
	}
	if uint64(tsig.Fudge) < ti {
		return ErrTime
	}

	return nil
}

// Create a wiredata buffer for the MAC calculation.
func tsigBuffer(msgbuf []byte, rr *TSIG, requestMAC string, timersOnly bool) ([]byte, error) {
	var buf []byte
	if rr.TimeSigned == 0 {
		rr.TimeSigned = uint64(time.Now().Unix())
	}
	if rr.Fudge == 0 {
		rr.Fudge = 300 // Standard (RFC) default.
	}

	// Replace message ID in header with original ID from TSIG
	binary.BigEndian.PutUint16(msgbuf[0:2], rr.OrigId)

	if requestMAC != "" {
		m := new(macWireFmt)
		m.MACSize = uint16(len(requestMAC) / 2)
		m.MAC = requestMAC
		buf = make([]byte, len(requestMAC)) // long enough
		n, err := packMacWire(m, buf)
		if err != nil {
			return nil, err
		}
		buf = buf[:n]
	}

	tsigvar := make([]byte, DefaultMsgSize)
	if timersOnly {
		tsig := new(timerWireFmt)
		tsig.TimeSigned = rr.TimeSigned
		tsig.Fudge = rr.Fudge
		n, err := packTimerWire(tsig, tsigvar)
		if err != nil {
			return nil, err
		}
		tsigvar = tsigvar[:n]
	} else {
		tsig := new(tsigWireFmt)
		tsig.Name = CanonicalName(rr.Hdr.Name)
		tsig.Class = ClassANY
		tsig.Ttl = rr.Hdr.Ttl
		tsig.Algorithm = CanonicalName(rr.Algorithm)
		tsig.TimeSigned = rr.TimeSigned
		tsig.Fudge = rr.Fudge
		tsig.Error = rr.Error
		tsig.OtherLen = rr.OtherLen
		tsig.OtherData = rr.OtherData
		n, err := packTsigWire(tsig, tsigvar)
		if err != nil {
			return nil, err
		}
		tsigvar = tsigvar[:n]
	}

	if requestMAC != "" {
		x := append(buf, msgbuf...)
		buf = append(x, tsigvar...)
	} else {
		buf = append(msgbuf, tsigvar...)
	}
	return buf, nil
}

// Strip the TSIG from the raw message.
func stripTsig(msg []byte) ([]byte, *TSIG, error) {
	// Copied from msg.go's Unpack() Header, but modified.
	s := cryptobyte.String(msg)

	var dh Header
	if !dh.unpack(&s) {
		return nil, nil, errTruncatedMessage
	}
	if dh.Arcount == 0 {
		return nil, nil, ErrNoSig
	}

	// Rcode, see msg.go Unpack()
	if int(dh.Bits&0xF) == RcodeNotAuth {
		return nil, nil, ErrAuth
	}

	_, err := unpackQuestions(dh.Qdcount, &s, msg)
	if err != nil {
		return nil, nil, err
	}

	_, err = unpackRRs(dh.Ancount, &s, msg)
	if err != nil {
		return nil, nil, err
	}

	_, err = unpackRRs(dh.Nscount, &s, msg)
	if err != nil {
		return nil, nil, err
	}

	for i := 0; i < int(dh.Arcount); i++ {
		rrOff := offset(s, msg)
		extra, err := unpackRR(&s, msg)
		if err != nil {
			return nil, nil, err
		}
		if extra.Header().Rrtype == TypeTSIG {
			// Adjust Arcount.
			arcount := binary.BigEndian.Uint16(msg[10:])
			binary.BigEndian.PutUint16(msg[10:], arcount-1)
			return msg[:rrOff], extra.(*TSIG), nil
		}
	}

	return nil, nil, ErrNoSig
}

*/
