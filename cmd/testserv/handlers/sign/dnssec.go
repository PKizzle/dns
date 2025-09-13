package sign

import (
	"fmt"
	"slices"

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
	for _, pair := range s.Pairs {
		n.RRs = append(n.RRs, pair.DNSKEY)
		n.RRs = append(n.RRs, pair.DNSKEY.ToDS(dns.SHA1).ToCDS())
		n.RRs = append(n.RRs, pair.DNSKEY.ToDS(dns.SHA256).ToCDS())
		n.RRs = append(n.RRs, pair.DNSKEY.ToCDNSKEY())
	}
	z.Set(n)

	return nil
}

type nsecfn struct {
	zone   *zone.Zone
	last   string
	bitmap []uint16
	ttl    uint32
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

// Walk is used when signing a zone. It generates all the NSECs that a zone needs.
func (nf *nsecfn) Walk(n zone.Node, auth bool) bool {
	if !auth {
		return true
	}
	println("ADDING")
	if nf.last != "" {
		nsec := &dns.NSEC{
			Hdr:        dns.Header{Name: nf.last, TTL: nf.ttl, Class: dns.ClassINET},
			NextDomain: n.Name,
			TypeBitMap: nf.bitmap,
		}
		nnsec := zone.Node{Name: nf.last, RRs: []dns.RR{nsec}}
		nnsec = nnsec
		fmt.Println(nsec.String())
		// nf.zone.Set(nnsec) // cant add while walking...
	}
	nf.last = n.Name
	nf.bitmap = types(n)
	return true
}
