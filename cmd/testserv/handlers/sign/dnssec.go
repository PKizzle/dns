package sign

import (
	"slices"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/dbfile/zone"
)

// Sign signs the zone with origin from s. It returns the signed zone.
func (s *Sign) Sign(origin string) (*zone.Zone, error) {
	z := zone.New(origin, s.Path)
	err := z.Load()
	if err != nil {
		return z, err
	}

	n := zone.Node{Name: origin}
	for _, pair := range s.KeyPairs {
		n.RRs = append(n.RRs, pair.DNSKEY)
		n.RRs = append(n.RRs, pair.DNSKEY.ToDS(dns.SHA1).ToCDS())
		n.RRs = append(n.RRs, pair.DNSKEY.ToDS(dns.SHA256).ToCDS())
		n.RRs = append(n.RRs, pair.DNSKEY.ToCDNSKEY())
	}
	z.Set(n)

	// Add nsecs + rrsig in the first pass.
	nf := &nsecfn{zone: z, keypairs: s.KeyPairs, ttl: s.ttl, origin: origin}
	z.AuthoritativeWalk(nf.Walk)
	for i := range nf.nsecs {
		z.Set(nf.nsecs[i])
	}
	z.Set(nf.Last(z.Origin))

	// Now walk again to sign the rest.
	rrset := []dns.RR{}
	rrsigs := []zone.Node{}
	incep, expir := lifetime(time.Now().UTC())

	z.AuthoritativeWalk(func(n zone.Node, auth bool) bool {
		if !auth || len(n.RRs) == 0 {
			return true
		}
		types := types(n, s.ttl)
		for _, t := range types {
			if t == dns.TypeRRSIG || t == dns.TypeNSEC {
				continue
			}
			rrset = []dns.RR{}
			for _, rr := range n.RRs {
				if dns.RRToType(rr) == t {
					rrset = append(rrset, rr)
				}
			}

			rrsignode := zone.Node{Name: n.Name, RRs: make([]dns.RR, 0, len(s.KeyPairs))}
			for _, pair := range s.KeyPairs {
				rrsig := dns.NewRRSIG(origin, pair.DNSKEY.Algorithm, pair.Tag, incep, expir)
				rrsig.Sign(pair.Signer, rrset, &dns.SignOption{})

				rrsignode.RRs = append(rrsignode.RRs, rrsig)
			}
			rrsigs = append(rrsigs, rrsignode)
		}
		return true
	})
	for i := range rrsigs {
		z.Set(rrsigs[i])
	}
	return z, nil
}

type nsecfn struct {
	zone     *zone.Zone
	origin   string
	keypairs []KeyPair
	now      time.Time

	last   string
	bitmap []uint16
	ttl    uint32

	nsecs []zone.Node
}

func types(n zone.Node, ttl uint32) []uint16 {
	// while looking at them anyway we set the ttl.
	types := []uint16{} // pool for this too?
	for _, rr := range n.RRs {
		types = append(types, dns.RRToType(rr))
		rr.Header().TTL = ttl
	}
	types = append(types, []uint16{dns.TypeRRSIG, dns.TypeNSEC}...)

	slices.Sort(types)
	return slices.Compact(types)
}

// Pooler for memory allocations! TODO(miek)

// Walk is used when signing a zone. It generates all the NSECs that a zone needs.
// We can't insert while walking, so we need save the nsec+rssig and insert them post walk.
func (nf *nsecfn) Walk(n zone.Node, auth bool) bool {
	if !auth || len(n.RRs) == 0 { // empty non-terminal
		return true
	}
	if nf.last != "" {
		nsecnode := nf.nsec(nf.origin)
		nf.nsecs = append(nf.nsecs, nsecnode)
	}
	nf.last = n.Name
	nf.bitmap = types(n, nf.ttl)
	return true
}

// Last creates the last NSEC, that loops back to the origin. Walk misses this.
func (nf *nsecfn) Last(origin string) zone.Node { return nf.nsec(origin) }

// nsec creates an NSEC + RRSIG(s) node from nf.
func (nf *nsecfn) nsec(origin string) zone.Node {
	nsec := &dns.NSEC{
		Hdr:        dns.Header{Name: nf.last, TTL: nf.ttl, Class: dns.ClassINET},
		NextDomain: origin,
		TypeBitMap: nf.bitmap,
	}
	nsecnode := zone.Node{Name: nf.last}
	nsecnode.RRs = append(nsecnode.RRs, nsec)

	for _, pair := range nf.keypairs {
		incep, expir := lifetime(nf.now)
		rrsig := dns.NewRRSIG(origin, pair.DNSKEY.Algorithm, pair.Tag, incep, expir)
		rrsig.Sign(pair.Signer, []dns.RR{nsec}, &dns.SignOption{})

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
