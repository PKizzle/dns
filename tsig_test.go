package dns

import (
	"encoding/binary"
	"strings"
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

const tsigSecret = "pRZgBrBvI4NAHZYhxmhs/Q=="

func TestTSIG(t *testing.T) {
	testcases := []struct {
		name        string
		alg         string
		option      TSIGOption
		transformFn func(m *Msg)
	}{
		{"signverify", tsigSecret, TSIGOption{}, nil},
		{"signverify-id", tsigSecret, TSIGOption{}, func(m *Msg) { binary.BigEndian.PutUint16(m.Data[0:2], 42) }},
		{"signverify-upper", strings.ToUpper(tsigSecret), TSIGOption{}, func(m *Msg) { binary.BigEndian.PutUint16(m.Data[0:2], 42) }},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMsgWithTSIG()
			if err := TSIGSign(m, HMAC(tc.alg), tc.option); err != nil {
				t.Fatalf("failed to sign: %s", err)
			}

			if tc.transformFn != nil {
				tc.transformFn(m)
			}

			if err := TSIGVerify(m, HMAC(tc.alg), tc.option); err != nil {
				t.Fatalf("failed to verify: %s", err)
			}
		})
	}
}
