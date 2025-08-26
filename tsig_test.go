package dns

import (
	"encoding/binary"
	"testing"
)

func newMsgWithTSIG() *Msg {
	m := NewMsg("miek.nl.", TypeMX)
	m.ID = 3

	tsig := NewTSIG("example.", HmacSHA256, 0)
	m.Pseudo = []RR{tsig}
	m.Pack()
	return m
}

var tsigSecret = "blaat"

func TestTSIG(t *testing.T) {
	// This plainly test if we can verify what we sign, without any timers or request mac.
	testcases := []struct {
		name        string
		transformFn func(m *Msg)
		err         error
	}{
		{"signverify", nil, nil},
		{"signverify-changed-id", func(m *Msg) { binary.BigEndian.PutUint16(m.Data[0:2], 42) }, nil},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMsgWithTSIG()
			option := TSIGOption{}
			hmac := TSIGHMAC{Secret: tsigSecret}
			if err := TSIGSign(m, hmac, &option); err != nil {
				t.Fatalf("failed to sign: %s", err)
			}

			if tc.transformFn != nil {
				tc.transformFn(m)
			}

			option.RequestMAC = "" // Negate this from TSIGSign, as TSIGVerify is supposed to be running on a different machine normally.

			err := TSIGVerify(m, hmac, &option)
			if err != tc.err {
				t.Fatalf("expecpted %v error, got: %s", tc.err, err)
			}
		})
	}
}
