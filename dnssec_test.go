package dns

import (
	"crypto/rsa"
	"testing"
)

func TestSignVerify(t *testing.T) {
	testcases := []struct {
		name string
		rrs  []RR
		err  error
	}{
		{
			"1rr",
			[]RR{
				&SRV{Hdr: Header{Name: "srv.miek.nl", Class: ClassINET, TTL: 600}, Port: 1000, Weight: 80, Target: "web1.miek.nl."},
				//				&HINFO{Hdr: Header{Name: "miek.nl.", Class: ClassINET, TTL: 600}, Cpu: "Pentium", Os: "Linux"},
			},
			nil,
		},
	}

	key := NewDNSKEY("miek.nl.", RSASHA256)
	priv, _ := key.Generate(1024)

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			sig := NewRRSIG("miek.nl", RSASHA256, RRToType(tc.rrs[0]), key.KeyTag(), uint8(dnsutilCount(tc.rrs[0].Header().Name)), 3600)
			err := sig.Sign(priv.(*rsa.PrivateKey), tc.rrs)
			if err != nil {
				t.Fatalf("failure to sign: %s", err)
			}

			err = sig.Verify(key, tc.rrs)
			if err != nil {
				t.Fatalf("failure to verify: %s", err)
			}
		})
	}
}
