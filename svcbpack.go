package dns

import (
	"slices"
	"sort"

	"codeberg.org/miekg/dns/svcb"
	"golang.org/x/crypto/cryptobyte"
)

func unpackSVCBPair(s *cryptobyte.String) ([]svcb.Pair, error) {
	var kvs []svcb.Pair
	for !s.Empty() {
		var (
			key  uint16
			data cryptobyte.String
		)
		if !s.ReadUint16(&key) || !s.ReadUint16LengthPrefixed(&data) {
			return nil, ErrUnpackOverflow
		}
		p := svcb.KeyToPair[key]
		if p == nil {
			return nil, &Error{err: "bad SVCB key"}
		}
		if err := svcb.Unpack(p, data); err != nil {
			return nil, err
		}
		if len(kvs) > 0 && svcb.PairToKey(p) <= svcb.PairToKey(kvs[len(kvs)-1]) {
			return nil, &Error{err: "SVCB keys not in strictly increasing order"}
		}
		kvs = append(kvs, p)
	}
	return kvs, nil
}

func packSVCBPair(pairs []svcb.Pair, msg []byte, off int) (int, error) {
	pairs = slices.Clone(pairs)
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Key() < pairs[j].Key()
	})
	prev := svcb_KeyReserved
	for _, el := range pairs {
		if el.Key() == prev {
			return len(msg), &Error{err: "repeated SVCB keys are not allowed"}
		}
		prev = el.Key()
		packed, err := el.pack()
		if err != nil {
			return len(msg), err
		}
		off, err = packUint16(uint16(el.Key()), msg, off)
		if err != nil {
			return len(msg), &Error{err: "overflow packing SVCB"}
		}
		off, err = packUint16(uint16(len(packed)), msg, off)
		if err != nil || off+len(packed) > len(msg) {
			return len(msg), &Error{err: "overflow packing SVCB"}
		}
		copy(msg[off:off+len(packed)], packed)
		off += len(packed)
	}
	return off, nil
}
