package dns

import (
	"crypto"
	"math/big"
	"testing"

	"codeberg.org/miekg/dns/rdata"
)

// A key whose exponent needs more than four bytes must still be readable: this
// is the shape DNSSEC zones actually carry, and the only reason it was rejected
// is that crypto/rsa holds the exponent in an int.
func TestPublicKeyRSABigReadsALargeExponent(t *testing.T) {
	// pir.org's key-signing key: RSASHA1, exponent 2^32+1 (five bytes).
	k := &DNSKEY{
		Hdr:    Header{Name: "pir.org.", Class: ClassINET, TTL: 3600},
		DNSKEY: rdata.DNSKEY{Flags: 257, Protocol: 3, Algorithm: RSASHA1, PublicKey: pirOrgKSK},
	}

	n, e := k.publicKeyRSABig()
	if n == nil {
		t.Fatal("a key with a five-byte exponent was rejected")
	}
	if want := big.NewInt(4294967297); e.Cmp(want) != 0 {
		t.Errorf("exponent = %v, want %v", e, want)
	}
	if bits := n.BitLen(); bits != 2048 {
		t.Errorf("modulus = %d bits, want 2048", bits)
	}
	// The same key through crypto/rsa's representation: still refused, which is
	// why the fallback exists.
	if k.publicKeyRSA() != nil {
		t.Error("crypto/rsa accepted the key, so this fallback is no longer needed")
	}
}

// The padding must be required to be exactly right. A verifier that skips over
// it rather than checking it accepts forged signatures, so this asserts that a
// block differing anywhere at all is refused.
func TestVerifyPKCS1v15BigRefusesAnythingButTheExactBlock(t *testing.T) {
	// A small, valid RSA key with a large exponent, built for the test.
	n, _ := new(big.Int).SetString(testBigModulus, 16)
	e := big.NewInt(4294967297)

	hashed := make([]byte, crypto.SHA256.Size())
	for i := range hashed {
		hashed[i] = byte(i)
	}

	// Nothing verifies against a signature of the wrong length.
	if err := verifyPKCS1v15Big(n, e, crypto.SHA256, hashed, make([]byte, 8)); err == nil {
		t.Error("a signature of the wrong length was accepted")
	}
	// Nor an all-zero block, which decrypts to zero and matches no padding.
	size := (n.BitLen() + 7) / 8
	if err := verifyPKCS1v15Big(n, e, crypto.SHA256, hashed, make([]byte, size)); err == nil {
		t.Error("an empty signature was accepted")
	}
	// Nor a digest of the wrong size for the algorithm named.
	if err := verifyPKCS1v15Big(n, e, crypto.SHA256, hashed[:16], make([]byte, size)); err == nil {
		t.Error("a digest of the wrong length was accepted")
	}
	// Nor an algorithm with no defined encoding here.
	if err := verifyPKCS1v15Big(n, e, crypto.MD5, hashed, make([]byte, size)); err == nil {
		t.Error("an algorithm with no defined DigestInfo was accepted")
	}
}
