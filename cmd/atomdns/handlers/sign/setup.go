package sign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"codeberg.org/miekg/dns/dnsutil"
	"golang.org/x/crypto/ed25519"
)

func (s *Sign) Setup(co *dnsserver.Controller) error {
	s.ttl = 3600
	s.pool = dns.NewPool(dns.MinMsgSize)
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.Zones = map[string]*zone.Zone{}
	s.Directory = co.Global.Root
	if co.Next() {
		args := co.RemainingArgs()
		if len(args) != 1 {
			return co.ArgErr()
		}
		s.Path = args[0]
		if !filepath.IsAbs(s.Path) {
			s.Path = filepath.Join(co.Global.Root, s.Path)
		}
		s.Directory = filepath.Dir(s.Path)
		for co.NextBlock(0) {
			switch co.Val() {
			case "ttl":
				args := co.RemainingArgs()
				if len(args) == 0 {
					return co.ArgErr()
				}
				ttl, err := strconv.ParseUint(args[0], 10, 32)
				if err != nil {
					return co.PropErr(err)
				}
				s.ttl = uint32(ttl)

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
					s.KeyPairs = append(s.KeyPairs, pair)
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
	for _, k := range s.KeyPairs {
		k.DNSKEY.Header().TTL = s.ttl
	}
	co.OnStartup(func() error {
		log.Info("Startup", "signing", filepath.Base(s.Path))
		for _, z := range s.Zones {
			_, err := os.Stat(z.Path)
			if errors.Is(err, os.ErrNotExist) {
				log.Error(fmt.Sprintf("Zone %q in %q does not exist", z.Origin, filepath.Base(z.Path)))
				return co.Err(err.Error())
			}

			expired, err := s.Expired(z.Origin)
			if !expired {
				log.Info(fmt.Sprintf("Zone %q in %q has valid signatures", z.Origin, filepath.Base(z.Path)))
				continue
			}
			zs, err := s.Sign(z.Origin)
			if err != nil {
				return co.Err(err.Error())
			}
			if err := s.Write(zs); err != nil {
				return co.Err(err.Error())
			}
		}
		return s.Resign()
	})
	co.OnShutdown(func() error {
		log.Info("Shutdown", "signing", filepath.Base(s.Path))
		s.cancel()
		return nil
	})
	return nil
}

// KeyPair holds DNSSEC key information, both the public and private components are stored here.
type KeyPair struct {
	*dns.DNSKEY
	Tag uint16
	crypto.Signer
}

func keypair(base string) (KeyPair, error) {
	p, err := os.ReadFile(base + ".key")
	if err != nil {
		return KeyPair{}, err
	}
	rr, err := dns.New(string(p))
	if err != nil {
		return KeyPair{}, err
	}
	if _, ok := rr.(*dns.DNSKEY); !ok {
		return KeyPair{}, fmt.Errorf("RR in %q is not a DNSKEY: %s", base+".key", dnsutil.TypeToString(dns.RRToType(rr)))
	}
	dnskey := rr.(*dns.DNSKEY)
	ksk := dnskey.Flags&(1<<8) == (1<<8) && dnskey.Flags&1 == 1
	if !ksk {
		return KeyPair{}, fmt.Errorf("DNSKEY is not a CSK/KSK")
	}

	if p, err = os.ReadFile(base + ".private"); err != nil {
		return KeyPair{}, err
	}
	privkey, err := dnskey.NewPrivate(string(p))
	if err != nil {
		return KeyPair{}, err
	}
	switch signer := privkey.(type) {
	case *ecdsa.PrivateKey:
		return KeyPair{DNSKEY: dnskey, Tag: dnskey.KeyTag(), Signer: signer}, nil
	case ed25519.PrivateKey:
		return KeyPair{DNSKEY: dnskey, Tag: dnskey.KeyTag(), Signer: signer}, nil
	case *rsa.PrivateKey:
		return KeyPair{DNSKEY: dnskey, Tag: dnskey.KeyTag(), Signer: signer}, nil
	default:
		return KeyPair{}, fmt.Errorf("unsupported algorithm %s", signer)
	}
}
