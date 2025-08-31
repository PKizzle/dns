package dns

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"math/big"
)

type CryptoSIG0 struct {
	CryptoSigner crypto.Signer
	PublicKey    *KEY
}

// We need SIG0Option as well here, because the request might be needed as well.

func (c CryptoSIG0) Key() *KEY             { return c.PublicKey }
func (c CryptoSIG0) Signer() crypto.Signer { return c.CryptoSigner }

func (c CryptoSIG0) Sign(s *SIG, p []byte) ([]byte, error) {
	var (
		off int
		err error
	)

	h, cryptohash, err := hashFromAlgorithm(s.Algorithm)
	if err != nil {
		return nil, err
	}
	sbuf := make([]byte, s.Len())
	if _, off, err = packRR(s, sbuf, 0, nil); err != nil {
		return nil, err
	}
	sbuf = sbuf[:off]

	// Write SIG rdata
	h.Write(sbuf)
	// Write message
	h.Write(p)

	return sign(c.Signer(), h.Sum(nil), cryptohash, s.Algorithm)
}

func (c CryptoSIG0) Verify(s *SIG, p []byte) error {
	var (
		off int
		err error
	)
	h, cryptohash, err := hashFromAlgorithm(s.Algorithm)
	if err != nil {
		return err
	}

	signature := s.Signature
	s.Signature = "" // omit
	defer func() { s.Signature = signature }()

	sbuf := make([]byte, s.Len())
	if _, off, err = packRR(s, sbuf, 0, nil); err != nil {
		return err
	}
	sbuf = sbuf[:off]

	// Write SIG rdata
	h.Write(sbuf)
	// Write message
	h.Write(p)

	binarysignature, _ := fromBase64([]byte(signature))
	switch s.Algorithm {
	case RSASHA1, RSASHA256, RSASHA512:
		return rsa.VerifyPKCS1v15(c.Key().publicKeyRSA(), cryptohash, h.Sum(nil), binarysignature)

	case ECDSAP256SHA256, ECDSAP384SHA384:
		r := new(big.Int).SetBytes(binarysignature[:len(binarysignature)/2])
		s := new(big.Int).SetBytes(binarysignature[len(binarysignature)/2:])
		if ecdsa.Verify(c.Key().publicKeyECDSA(), h.Sum(nil), r, s) {
			return nil
		}
		return ErrSig

	case ED25519:
		if ed25519.Verify(c.Key().publicKeyED25519(), h.Sum(nil), binarysignature) {
			return nil
		}
		return ErrSig

	}
	return ErrKeyAlg
}
