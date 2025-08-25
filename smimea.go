package dns

import (
	"crypto/x509"
)

// Sign creates a SMIMEA record from an SSL certificate.
func (r *SMIMEA) Sign(usage, selector, matchingType int, cert *x509.Certificate) (err error) {
	r.Hdr.t = TypeSMIMEA
	r.Usage = uint8(usage)
	r.Selector = uint8(selector)
	r.MatchingType = uint8(matchingType)

	r.Certificate, err = certificateToDANE(r.Selector, r.MatchingType, cert)
	return err
}

// Verify verifies a SMIMEA record against a TLS certificate. If it is OK a nil error is returned.
func (r *SMIMEA) Verify(cert *x509.Certificate) error {
	c, err := certificateToDANE(r.Selector, r.MatchingType, cert)
	if err != nil {
		return err // Not also ErrSig?
	}
	if r.Certificate == c {
		return nil
	}
	return ErrSig // ErrSig, really?
}
