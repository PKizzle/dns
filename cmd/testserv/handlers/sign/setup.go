package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/dbfile/zone"
	"codeberg.org/miekg/dns/cmd/testserv/internal/dnsserver"
	"codeberg.org/miekg/dns/dnsutil"
	"golang.org/x/crypto/ed25519"
)

func (s *Sign) Setup(co dnsserver.Controller) error {
	s.ttl = 3600

	if co.Next() {
		args := co.RemainingArgs()
		if len(args) != 1 {
			return co.ArgErr()
		}
		s.Path = args[0]
		if !filepath.IsAbs(s.Path) {
			s.Path = filepath.Join(co.Global.Root, s.Path)
		}
		for co.NextBlock() {
			switch co.Val() {
			case "key":
				args := co.RemainingArgs()
				if len(args) == 0 {
					return co.ArgErr()
				}
				for i := range args {
					pair, err := keypair(args[i])
					if err != nil {
						return co.PropErr(err)
					}
					pair.DNSKEY.Header().TTL = s.ttl
					s.Pairs = append(s.Pairs, pair)
				}
			case "directory":
				if !co.Next() {
					return co.ArgErr()
				}
				s.Directory = co.Val()
				if !filepath.IsAbs(s.Directory) {
					s.Directory = filepath.Join(co.Global.Root, s.Directory)
				}
			default:
				return co.ArgErr()
			}
		}
	}
	for _, z := range co.Keys() {
		s.Zones[dnsutil.Canonical(z)] = zone.New(z, s.Path)
	}
	return nil
}

// Pair holds DNSSEC key information, both the public and private components are stored here.
type Pair struct {
	*dns.DNSKEY
	Tag uint16
	crypto.Signer
}

func keypair(base string) (Pair, error) {
	p, err := os.ReadFile(base + ".key")
	if err != nil {
		return Pair{}, err
	}
	rr, err := dns.New(string(p))
	if err != nil {
		return Pair{}, err
	}
	if _, ok := rr.(*dns.DNSKEY); !ok {
		return Pair{}, fmt.Errorf("RR in %q is not a DNSKEY: %s", base+".key", dnsutil.TypeToString(dns.RRToType(rr)))
	}
	dnskey := rr.(*dns.DNSKEY)
	ksk := dnskey.Flags&(1<<8) == (1<<8) && dnskey.Flags&1 == 1
	if !ksk {
		return Pair{}, fmt.Errorf("DNSKEY is not a CSK/KSK")
	}

	if p, err = os.ReadFile(base + ".private"); err != nil {
		return Pair{}, err
	}
	privkey, err := dnskey.NewPrivate(string(p))
	if err != nil {
		return Pair{}, err
	}
	switch signer := privkey.(type) {
	case *ecdsa.PrivateKey:
		return Pair{DNSKEY: dnskey, Tag: dnskey.KeyTag(), Signer: signer}, nil
	case ed25519.PrivateKey:
		return Pair{DNSKEY: dnskey, Tag: dnskey.KeyTag(), Signer: signer}, nil
	case *rsa.PrivateKey:
		return Pair{DNSKEY: dnskey, Tag: dnskey.KeyTag(), Signer: signer}, nil
	default:
		return Pair{}, fmt.Errorf("unsupported algorithm %s", signer)
	}
}
