package dns

import (
	"encoding/hex"

	"golang.org/x/crypto/cryptobyte"
)

// Should be generated it is not yet

func (o *NSID) unpack(s *cryptobyte.String) error {
	o.Nsid = hex.EncodeToString(*s)
	return nil
}

func (o *NSID) pack(msg []byte, off int) (int, error) {
	return hex.Decode(msg[off:], []byte(o.Nsid))
}

func (o *PADDING) unpack(s *cryptobyte.String) error {
	return nil
}

func (o *PADDING) pack(msg []byte, off int) (int, error) {
	return 0, nil
}
