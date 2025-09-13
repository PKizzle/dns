package sign

import (
	"slices"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/dbfile/zone"
)

func (s *Sign) Sign(origin, path string) error {
	z := zone.New(origin, path)
	err := z.Load()
	if err != nil {
		return err
	}

	n := zone.Node{Name: origin}
	for _, pair := range s.KeyPairs {
		n.RRs = append(n.RRs, pair.DNSKEY)
		n.RRs = append(n.RRs, pair.DNSKEY.ToDS(dns.SHA1).ToCDS())
		n.RRs = append(n.RRs, pair.DNSKEY.ToDS(dns.SHA256).ToCDS())
		n.RRs = append(n.RRs, pair.DNSKEY.ToCDNSKEY())
	}
	z.Set(n)

	return nil
}

type nsecfn struct {
	zone     *zone.Zone
	keypairs []KeyPair
	now      time.Time

	last   string
	bitmap []uint16
	ttl    uint32

	nsecs []zone.Node
}

func types(n zone.Node) []uint16 {
	types := make([]uint16, 0, len(n.RRs))
	for _, rr := range n.RRs {
		types = append(types, dns.RRToType(rr))
	}

	slices.Sort(types)
	slices.Compact(types)
	return types
}

// Pooler for memory allocations!

// Walk is used when signing a zone. It generates all the NSECs that a zone needs.
// We can't insert while walking, so we need save the nsec+rssig and insert them post walk.
func (nf *nsecfn) Walk(n zone.Node, auth bool) bool {
	if !auth {
		return true
	}
	if nf.last != "" {
		nsec := &dns.NSEC{
			Hdr:        dns.Header{Name: nf.last, TTL: nf.ttl, Class: dns.ClassINET},
			NextDomain: n.Name,
			TypeBitMap: nf.bitmap,
		}
		nsecnode := zone.Node{Name: nf.last, RRs: make([]dns.RR, 0, 2)}
		nsecnode.RRs = append(nsecnode.RRs, nsec)

		for _, pair := range nf.keypairs {
			incep, expir := lifetime(nf.now)
			rrsig := dns.NewRRSIG(nf.last, pair.DNSKEY.Algorithm, pair.Tag, nf.ttl, incep, expir)
			rrsig.Sign(pair.Signer, []dns.RR{rrsig}, &dns.SignOption{})

			nsecnode.RRs = append(nsecnode.RRs, rrsig)
		}
		nf.nsecs = append(nf.nsecs, nsecnode)
	}
	nf.last = n.Name
	nf.bitmap = types(n)
	return true
}

// Last creates the last NSEC, that loops back to the origin. Walk misses this.
func (nf *nsecfn) Last(origin string) zone.Node {
	nsec := &dns.NSEC{
		Hdr:        dns.Header{Name: nf.last, TTL: nf.ttl, Class: dns.ClassINET},
		NextDomain: origin,
		TypeBitMap: nf.bitmap,
	}
	nsecnode := zone.Node{Name: nf.last, RRs: make([]dns.RR, 0, 2)}
	nsecnode.RRs = append(nsecnode.RRs, nsec)

	for _, pair := range nf.keypairs {
		incep, expir := lifetime(nf.now)
		rrsig := dns.NewRRSIG(nf.last, pair.DNSKEY.Algorithm, pair.Tag, nf.ttl, incep, expir)
		rrsig.Sign(pair.Signer, []dns.RR{rrsig}, &dns.SignOption{})

		nsecnode.RRs = append(nsecnode.RRs, rrsig)
	}
	return nsecnode
}

// lifetime returns signature incep, expire timestamp used in the signature creation.
func lifetime(now time.Time) (uint32, uint32) {
	incep := uint32(now.Add(signatureInception).Add(inceptionJitter).Unix())
	expir := uint32(now.Add(signatureExpire).Add(expirationJitter).Unix())
	return incep, expir
}
