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

var tsigSecret = []byte("blaat")

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
			hmac := HmacTSIG{Secret: tsigSecret}
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

func TestTSIGSectionExtra(t *testing.T) {
	m := newMsgWithTSIG()
	option := TSIGOption{}
	hmac := HmacTSIG{Secret: tsigSecret}
	if err := TSIGSign(m, hmac, &option); err != nil {
		t.Fatalf("failed to sign: %s", err)
	}
	// After tsig signed, we expect m.Extra == 0, m.Pseudo == 1 and the binary ArCount must be 1
	if len(m.Extra) != 0 {
		t.Errorf("expected m.Extra len to be 0, got %d", len(m.Extra))
	}
	if len(m.Pseudo) != 1 {
		t.Errorf("expected m.Pseudo len to be 1, got %d", len(m.Pseudo))
	}
	arcount := binary.BigEndian.Uint16(m.Data[10:])
	if arcount != 1 {
		t.Errorf("expected binary arcount to be 1, got %d", arcount)
	}
}
