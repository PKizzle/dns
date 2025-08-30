package dns

import (
	"slices"

	"codeberg.org/miekg/dns/internal/unpack"
	"codeberg.org/miekg/dns/svcb"
	"golang.org/x/crypto/cryptobyte"
)

func unpackSVCB(s *cryptobyte.String) ([]svcb.Pair, error) {
	var pairs []svcb.Pair
	key := uint16(0)
	for !s.Empty() {
		var data *cryptobyte.String
		if !s.ReadUint16(&key) || !s.ReadUint16LengthPrefixed(data) {
			return nil, unpack.ErrOverflow
		}
		pairFn := svcb.KeyToPair(key)
		if pairFn == nil {
			return nil, &Error{err: "bad SVCB key"}
		}
		pair := pairFn()

		if err := svcb.Unpack(pair, data); err != nil {
			return nil, err
		}
		pairs = append(pairs, pair)
	}
	return pairs, nil
}

func packSVCB(pairs []svcb.Pair, msg []byte, off int) (off1 int, err error) {
	pairs = slices.Clone(pairs)
	prev := svcb.KeyReserved
	for _, pair := range pairs {
		key := svcb.PairToKey(pair)
		if key == prev {
			return len(msg), &Error{err: "repeated SVCB keys are not allowed"}
		}
		prev = key
		off, err = svcb.Pack(pair, msg, off)
		if err != nil {
			return len(msg), err
		}
	}
	return off, nil
}
