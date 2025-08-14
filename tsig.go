package dns

import (
	"encoding/binary"
	"strconv"
	"strings"
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
