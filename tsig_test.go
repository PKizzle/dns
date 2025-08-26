package dns

import (
	"encoding/binary"
	"testing"
	"time"
)

func newMsgWithTSIG() *Msg {
	m := &Msg{MsgHeader: MsgHeader{ID: 3, RecursionDesired: true}}
	mx := &MX{Hdr: Header{Name: "miek.nl.", Class: ClassINET}}
	m.Question = []RR{mx}

	tsig := &TSIG{Hdr: Header{Name: "example.", Class: ClassANY}}
	tsig.Algorithm = HmacSHA256
	tsig.TimeSigned = uint64(time.Now().Unix())
	tsig.OrigID = m.ID

	m.Pseudo = append(m.Pseudo, tsig)
	m.Pack()
	return m
}

var tsigSecret = []byte("blaat")

func TestTSIG(t *testing.T) {
	// This plainly test if we can verify what we sign, without any timers or request mac.
	testcases := []struct {
		name        string
		option      TSIGOption
		transformFn func(m *Msg)
		err         error
	}{
		{"signverify", TSIGOption{}, nil, nil},
		{"signverify-changed-id", TSIGOption{}, func(m *Msg) { binary.BigEndian.PutUint16(m.Data[0:2], 42) }, nil},
		{"signverify-upper", TSIGOption{}, func(m *Msg) { binary.BigEndian.PutUint16(m.Data[0:2], 42) }, nil},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMsgWithTSIG()
			hmac := TSIGHMAC{Secret: tsigSecret}
			if err := TSIGSign(m, hmac, &tc.option); err != nil {
				t.Fatalf("failed to sign: %s", err)
			}

			if tc.transformFn != nil {
				tc.transformFn(m)
			}

			tc.option.RequestMAC = "" // Negate this from TSIGSign, as TSIGVerify is supposed to be running on a different machine normally.

			err := TSIGVerify(m, hmac, &tc.option)
			if err != tc.err {
				t.Fatalf("execpted %v error, got: %s", tc.err, err)
			}
		})
	}
}
