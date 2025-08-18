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

// Sign fills out the TSIG record. This should be a "stub" TSIG RR with the algorithm, key name
// (owner name of the RR), time fudge (defaults to 300 seconds, if zero) and the current
// time. The TSIG MAC is saved in that RR. When Sign is called for the first time
// options.RequestMAC should be empty and options.TimersOnly should be false.
//
// The completed TSIG is then appended to m.Data and to m.Pseudo. The additional record count is updated
// in m.Data to reflect this addition.
func (rr *TSIG) Sign(k TSIGSigner, m *Msg, options TSIGOption) error {
	// restore msg ID, as the origID is used to calculate hash, and set in m.Data.
	binary.BigEndian.PutUint16(m.Data[0:2], rr.OrigID)
	defer func() {
		binary.BigEndian.PutUint16(m.Data[0:2], m.ID)
	}()
	macbuf, err := rr.mac(m, options)
	if err != nil {
		return err
	}
	mac, err := k.Sign(rr, macbuf)
	if err != nil {
		return err
	}

	rr.MAC = hex.EncodeToString(mac)
	rr.MACSize = uint16(len(rr.MAC) / 2)
	if rr.TimeSigned == 0 {
		rr.TimeSigned = uint64(time.Now().Unix())
	}
	if rr.Fudge == 0 {
		rr.Fudge = 300 // Standard (RFC) default.
	}
	// clear otherdata 'n stuff?
	t := make([]byte, rr.Len())
	off, err := PackRR(rr, t, 0, nil)
	if err != nil {
		return err
	}
	t = t[:off]

	m.Data = append(m.Data, t...)
	// Update the ArCount directly in the buffer. And add to pseudo
	binary.BigEndian.PutUint16(m.Data[10:], uint16(len(m.Extra)+int(m.ps)+1))
	m.Pseudo = append(m.Pseudo, rr)
	return nil
}

// Verify uses the TSIG record to verify the data in the message. In binary TSIG record should be still
// attached to m.Data and must be the last RR in the message. On successful verification, the TSIG record will
// be removed from m.Data but left in m.Pseudo (additional record count will be updated), and a nil error is returned.
func (rr *TSIG) Verify(k TSIGVerifier, m *Msg, options TSIGOption) error {
	lastrr := len(m.Question) + len(m.Answer) + len(m.Extra) + int(m.ps) - 1
	if lastrr < 1 {
		return ErrNoTSIG
	}

	last := jump.To(lastrr, m.Data)
	if last == 0 {
		return ErrNoTSIG
	}
	m.Data = m.Data[:last]
	macbuf, err := rr.mac(m, options)
	if err != nil {
		return err
	}
	if err := k.Verify(rr, macbuf, options); err != nil {
		return err
	}

	now := uint64(time.Now().Unix())
	// Fudge factor works both ways. A message can arrive before it was signed because of clock skew.
	// We check this after verifying the signature, following draft-ietf-dnsop-rfc2845bis
	// instead of RFC2845, in order to prevent a security vulnerability as reported in CVE-2017-3142/3143.
	fudge := now - rr.TimeSigned
	if now < rr.TimeSigned {
		fudge = rr.TimeSigned - now
	}
	if uint64(rr.Fudge) < fudge {
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
