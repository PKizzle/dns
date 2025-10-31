package dns_test

import (
	"sort"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
)

func TestZONEMD(t *testing.T) {
	var testcases = []struct {
		name   string
		zone   string
		zonemd *dns.ZONEMD
	}{
		{
			name: "simple-example-rfc8976",
			zone: `
example.      86400  IN  SOA     ns1 admin 2018031900 1800 900 604800 86400
              86400  IN  NS      ns1
              86400  IN  NS      ns2
              86400  IN  ZONEMD  2018031900 1 1 c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c
ns1           3600   IN  A       203.0.113.63
ns2           3600   IN  AAAA    2001:db8::63
`,
			zonemd: dnstest.New(`example. 3600  IN  ZONEMD  2018031900 1 1 c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c`).(*dns.ZONEMD),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			zone := []dns.RR{}
			z := dns.NewZoneParser(strings.NewReader(tc.zone), "example.", "<test>")
			for rr, ok := z.Next(); ok; rr, ok = z.Next() {
				zone = append(zone, rr)
			}
			zonemd := dns.NewZONEMD("example.", dns.ZONEMDSchemeSimple, dns.ZONEMDHashSHA384)
			sort.Sort(dns.RRset(zone))
			zonemd.Sign(zone, &dns.ZONEMDOption{})
			if zonemd.Digest != tc.zonemd.Digest {
				t.Fatalf("expected digest %q, got %q", tc.zonemd.Digest, zonemd.Digest)
			}
		})
	}
}
