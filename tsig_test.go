package dns

import (
	"bytes"
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
	testcases := []struct {
		name        string
		secret      SecretMsgFunc
		option      TSIGOption
		transformFn func(m *Msg)
		err         error
	}{
		{"signverify", func(m *Msg) ([]byte, error) { return tsigSecret, nil }, TSIGOption{}, nil, nil},
		{"signverify-changed-id", func(m *Msg) ([]byte, error) { return tsigSecret, nil }, TSIGOption{}, func(m *Msg) { binary.BigEndian.PutUint16(m.Data[0:2], 42) }, nil},
		{"signverify-upper", func(m *Msg) ([]byte, error) { return bytes.ToUpper(tsigSecret), nil }, TSIGOption{}, func(m *Msg) { binary.BigEndian.PutUint16(m.Data[0:2], 42) }, nil},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMsgWithTSIG()
			if err := TSIGSign(m, tc.secret, TSIGHMAC, tc.option); err != nil {
				t.Fatalf("failed to sign: %s", err)
			}

			if tc.transformFn != nil {
				tc.transformFn(m)
			}

			err := TSIGVerify(m, tc.secret, TSIGHMAC, tc.option)
			if err != tc.err {
				t.Fatalf("execpted %v error, got: %s", tc.err, err)
			}
		})
	}
}
