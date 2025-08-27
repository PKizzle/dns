package dns

import (
	"encoding/hex"
	"time"

	"codeberg.org/miekg/dns/internal/jump"
	"codeberg.org/miekg/dns/internal/pack"
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

// TSIGSign fills out the TSIG record in m. This should be a "stub" TSIG RR with the algorithm, key name
// (owner name of the RR), time fudge (defaults to 300 seconds, if zero).
// When Sign is called for the first time: options.RequestMAC should be empty and options.TimersOnly should be false.
// When this function returns options.RequestMAC will have the MAC as calculated.
func TSIGSign(m *Msg, k TSIGSigner, options *TSIGOption) error {
	if len(m.Data) == 0 {
		if err := m.Pack(); err != nil {
			return err
		}
	}

	if m.ps == 0 {
		return ErrNoTSIG
	}

	t := hasTSIG(m)
	if t == nil {
		return ErrNoTSIG
	}

	last := len(m.Ns) + len(m.Answer) + len(m.Extra) + int(m.ps) - 1 // skip question as 0th, is the first after question
	if last < 0 {
		return ErrNoTSIG
	}
	off := jump.To(last, m.Data)
	if off == 0 {
		return ErrNoTSIG
	}

	m.Data = m.Data[:off]
	arcount := uint16(len(m.Extra) + int(m.ps-1))
	pack.Uint16(arcount, m.Data, 10) // decrease additional section count, because we removed the TSIG

	macbuf, err := t.mac(m, *options)
	if err != nil {
		return err
	}

	mac, err := k.Sign(t, macbuf)
	if err != nil {
		return err
	}

	t.OrigID = m.ID
	t.MAC = hex.EncodeToString(mac)
	t.MACSize = uint16(len(t.MAC) / 2)
	if t.TimeSigned == 0 {
		t.TimeSigned = uint64(time.Now().Unix())
	}

	tbuf := make([]byte, t.Len())
	if off, err = PackRR(t, tbuf, 0, nil); err != nil {
		return err
	}
	tbuf = tbuf[:off]

	m.Data = append(m.Data, tbuf...)
	options.RequestMAC = t.MAC

	pack.Uint16(arcount+1, m.Data, 10) // and +1 after we done for the new and improved TSIG that is added
	return nil
}

// TSIGVerify verifies the TSIG on a message. On success a nil error is returned. The TSIG record is removed
// from m.Data, but left in the unpacked message m. TODO(miek):
// When this function returns options.RequestMAC will have the MAC seen on the TSIG.
func TSIGVerify(m *Msg, k TSIGVerifier, options *TSIGOption) error {
	if len(m.Data) == 0 {
		if err := m.Pack(); err != nil {
			return err
		}
	}

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

	// Sign unless there is a key or MAC validation error (RFC 8945 5.3.2).
	if tsig.Error == RcodeBadKey {
		return ErrKey
	}
	if tsig.Error == RcodeBadSig {
		return ErrSig
	}

	last := len(m.Answer) + len(m.Ns) + len(m.Extra) + int(m.ps) - 1
	if last < 0 {
		return ErrNoTSIG
	}
	off := jump.To(last, m.Data)
	if off == 0 {
		return ErrNoTSIG
	}

	m.Data = m.Data[:off]
	arcount := uint16(len(m.Extra) + int(m.ps-1))
	pack.Uint16(arcount, m.Data, 10) // decrease additional section count, because we removed the TSIG

	// restore msg ID, as the origID is used to calculate hash, and set in m.Data.
	pack.Uint16(tsig.OrigID, m.Data, 0)
	defer func() {
		pack.Uint16(m.ID, m.Data, 0)
	}()

	macbuf, err := tsig.mac(m, *options)
	if err != nil {
		return err
	}
	if err := k.Verify(tsig, macbuf, *options); err != nil {
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
	pack.Uint16(arcount+1, m.Data, 10) // restore arcount
	options.RequestMAC = tsig.MAC
	return nil
}

type TSIGOption struct {
	TimersOnly bool
	RequestMAC string
}

type (
	TSIGSigner interface {
		// Sign is passed the to-be-signed binary data extracted from the DNS message in p. It should return signature or an error.
		Sign(t *TSIG, p []byte) ([]byte, error)
		// Key returns the key to sign with.
		Key() []byte
	}

	TSIGVerifier interface {
		// Verify is passed the binary data with the TSIG octets and the TSIG RR. If the signature is valid it will return nil, otherwise an error.
		Verify(t *TSIG, p []byte, options TSIGOption) error
		// Key returns the key to verify with.
		Key() []byte
	}
)

func hasTSIG(m *Msg) *TSIG {
	for i := range m.Pseudo {
		if t, ok := m.Pseudo[i].(*TSIG); ok {
			return t
		}
	}
	return nil
}
