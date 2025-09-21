package dns

import (
	"slices"

	"codeberg.org/miekg/dns/deleg"
	"codeberg.org/miekg/dns/internal/unpack"
	"golang.org/x/crypto/cryptobyte"
)

func unpackDELEG(s *cryptobyte.String) ([]deleg.Info, error) {
	var infos []deleg.Info
	key := uint16(0)
	for !s.Empty() {
		var data cryptobyte.String
		if !s.ReadUint16(&key) || !s.ReadUint16LengthPrefixed(&data) {
			return nil, unpack.ErrOverflow
		}
		infoFn := deleg.KeyToInfo(key)
		if infoFn == nil {
			return nil, &Error{err: "bad DELEG key"}
		}
		info := infoFn()

		if err := deleg.Unpack(info, &data); err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}
	return infos, nil
}

func packDELEG(infos []deleg.Info, msg []byte, off int) (off1 int, err error) {
	infos = slices.Clone(infos)
	prev := deleg.KeyReserved
	for _, info := range infos {
		key := deleg.InfoToKey(info)
		if key == prev {
			return len(msg), &Error{err: "repeated DELEG keys are not allowed"}
		}
		prev = key
		off, err = deleg.Pack(info, msg, off)
		if err != nil {
			return len(msg), err
		}
	}
	return off, nil
}
