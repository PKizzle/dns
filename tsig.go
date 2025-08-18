package dns

import (
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns/internal/jump"
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

// TSIGSign fills out the TSIG record in m. This should be a "stub" TSIG RR with the algorithm, key name
// (owner name of the RR), time fudge (defaults to 300 seconds, if zero) The TSIG MAC is saved in that RR.
// When Sign is called for the first time: options.RequestMAC should be empty and options.TimersOnly should be false.
func TSIGSign(m *Msg, k TSIGSigner, options TSIGOption) error {
	if m.ps == 0 {
		return ErrNoTSIG
	}

	var tsig *TSIG
	for _, rr := range m.Pseudo {
		if x, ok := rr.(*TSIG); ok {
			tsig = x
			break
		}
	}
	if tsig == nil {
		return ErrNoTSIG
	}

	lastrr := len(m.Question) + len(m.Answer) + len(m.Extra) + int(m.ps) - 1
	if lastrr < 1 {
		return ErrNoTSIG
	}
	last := jump.To(lastrr, m.Data)
	if last == 0 {
		return ErrNoTSIG
	}

	// restore msg ID, as the origID is used to calculate hash, and set in m.Data.
	binary.BigEndian.PutUint16(m.Data[0:2], tsig.OrigID)
	defer func() {
		binary.BigEndian.PutUint16(m.Data[0:2], m.ID)
	}()

	m.Data = m.Data[:last]
	macbuf, err := tsig.mac(m, options)
	if err != nil {
		return err
	}
	mac, err := k.Sign(tsig, macbuf)
	if err != nil {
		return err
	}

	tsig.MAC = hex.EncodeToString(mac)
	tsig.MACSize = uint16(len(tsig.MAC) / 2)
	if tsig.TimeSigned == 0 {
		tsig.TimeSigned = uint64(time.Now().Unix())
	}
	if tsig.Fudge == 0 {
		tsig.Fudge = 300 // Standard (RFC) default.
	}

	t := make([]byte, tsig.Len())
	off, err := PackRR(tsig, t, 0, nil)
	if err != nil {
		return err
	}
	t = t[:off]

	m.Data = append(m.Data, t...)
	return nil
}

// TSIGVerify verifies the TSIG on a message. On success a nil error is returned. The TSIG record is removed
// from m.Data, but left in the unpacked message m.
func TSIGVerify(m *Msg, k TSIGVerifier, options TSIGOption) error {
	if m.ps == 0 {
		return ErrNoTSIG
	}

	var tsig *TSIG
	for _, rr := range m.Pseudo {
		if x, ok := rr.(*TSIG); ok {
			tsig = x
			break
		}
	}
	if tsig == nil {
		return ErrNoTSIG
	}

	lastrr := len(m.Question) + len(m.Answer) + len(m.Extra) + int(m.ps) - 1
	if lastrr < 1 {
		return ErrNoTSIG
	}
	last := jump.To(lastrr, m.Data)
	if last == 0 {
		return ErrNoTSIG
	}

	// restore msg ID, as the origID is used to calculate hash, and set in m.Data.
	binary.BigEndian.PutUint16(m.Data[0:2], tsig.OrigID)
	defer func() {
		binary.BigEndian.PutUint16(m.Data[0:2], m.ID)
	}()

	m.Data = m.Data[:last]
	macbuf, err := tsig.mac(m, options)
	if err != nil {
		return err
	}
	if err := k.Verify(tsig, macbuf, options); err != nil {
		return err
	}

	now := uint64(time.Now().Unix())
	// Fudge factor works both ways. A message can arrive before it was signed because of clock skew.
	// We check this after verifying the signature, following draft-ietf-dnsop-rfc2845bis
	// instead of RFC2845, in order to prevent a security vulnerability as reported in CVE-2017-3142/3143.
	fudge := now - tsig.TimeSigned
	if now < tsig.TimeSigned {
		fudge = tsig.TimeSigned - now
	}
	if uint64(tsig.Fudge) < fudge {
		return ErrTime
	}
	return nil
}

type TSIGOption struct {
	TimersOnly bool
	RequestMAC string
}

type (
	TSIGSigner interface {
		// Sign is passed the to-be-signed binary data extracted from the DNS message in. It should return
		// signature or an error.
		Sign(t *TSIG, p []byte) ([]byte, error)
	}

	TSIGVerifier interface {
		// Verify is passed the binary data with the TSIG octets and the TSIG RR. If the signature is valid it will return nil, otherwise an error.
		Verify(t *TSIG, p []byte, options TSIGOption) error
	}
)
