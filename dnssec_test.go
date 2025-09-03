package dns

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"testing"
)

func TestDNSSECSignVerify(t *testing.T) {
	// Add wildcard, sorting of RRs. etc.
	testcases := []struct {
		name      string
		algorithm uint8
		bitsize   int
		rrs       []RR
	}{
		{
			"rsasha256", RSASHA256, 1024,
			[]RR{
				&SRV{Hdr: Header{Name: "srv.miek.nl", Class: ClassINET, TTL: 600}, Port: 1000, Weight: 80, Target: "web1.miek.nl."},
				//				&HINFO{Hdr: Header{Name: "miek.nl.", Class: ClassINET, TTL: 600}, Cpu: "Pentium", Os: "Linux"},
			},
		},
		{
			"ecdsap256sha256", ECDSAP256SHA256, 256,
			[]RR{
				&SRV{Hdr: Header{Name: "srv.miek.nl", Class: ClassINET, TTL: 600}, Port: 1000, Weight: 80, Target: "web1.miek.nl."},
			},
		},
		{
			"ed25519", ED25519, 256,
			[]RR{
				&SRV{Hdr: Header{Name: "srv.miek.nl", Class: ClassINET, TTL: 600}, Port: 1000, Weight: 80, Target: "web1.miek.nl."},
			},
		},
	}

	options := &SignOption{}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var err error

			key := NewDNSKEY("miek.nl.", tc.algorithm)
			priv, _ := key.Generate(tc.bitsize)

			sig := NewRRSIG("miek.nl", tc.algorithm, key.KeyTag())
			switch tc.algorithm {
			case RSASHA256:
				err = sig.Sign(priv.(*rsa.PrivateKey), tc.rrs, options)
			case ECDSAP256SHA256:
				err = sig.Sign(priv.(*ecdsa.PrivateKey), tc.rrs, options)
			case ED25519:
				err = sig.Sign(priv.(ed25519.PrivateKey), tc.rrs, options)
			}
			if err != nil {
				t.Fatalf("failure to sign: %s", err)
			}

			err = sig.Verify(key, tc.rrs, options)
			if err != nil {
				t.Fatalf("failure to verify: %s", err)
			}
		})
	}
}

func TestDNSSECKeyTag(t *testing.T) {
	testcases := []struct {
		rr  RR
		tag uint16
	}{
		{
			dnstestNew("test.  IN DNSKEY  257 3 1 AwEAAcntNdoMnY8pvyPcpDTAaiqHyAhf53XUBANq166won/fjBFvmuzhTuP5r4el/pV0tzEBL73zpoU48BqF66uiL+qRijXCySJiaBUvLNll5rpwuduAOoVpmwOmkC4fV6izHOAx/Uy8c+pYP0YR8+1P7GuTFxgnMmt9sUGtoe+la0X/"),
			27461,
		},
		{
			dnstestNew("test.  IN DNSKEY  257 3 1 AwEAAf0bKO/m45ylk5BlSLmQHQRBLx1m/ZUXvyPFB387bJXxnTk6so3ub97L1RQ+8bOoiRh3Qm5EaYihjco7J8b/W5WbS3tVsE79nY584RfTKT2zcZ9AoFP2XLChXxPIf/6l0H9n6sH0aBjsG8vabEIp8e06INM3CXVPiMRPPeGNa0Ub"),
			27461,
		},
		{
			dnstestNew("example.net. 3600 IN DNSKEY 257 3 14 xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40"),
			10771,
		},
	}
	for i, tc := range testcases {
		got := tc.rr.(*DNSKEY).KeyTag()
		if got != tc.tag {
			t.Errorf("test %d, expected %d, got %d", i, tc.tag, got)
		}
	}
}
