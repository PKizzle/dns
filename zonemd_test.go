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

		{
			name: "root-servers-rfc8976",
			zone: `
root-servers.net.     3600000 IN  SOA     a.root-servers.net. nstld.verisign-grs.com. 2018091100 14400 7200 1209600 3600000
root-servers.net.     3600000 IN  NS      a.root-servers.net.
root-servers.net.     3600000 IN  NS      b.root-servers.net.
root-servers.net.     3600000 IN  NS      c.root-servers.net.
root-servers.net.     3600000 IN  NS      d.root-servers.net.
root-servers.net.     3600000 IN  NS      e.root-servers.net.
root-servers.net.     3600000 IN  NS      f.root-servers.net.
root-servers.net.     3600000 IN  NS      g.root-servers.net.
root-servers.net.     3600000 IN  NS      h.root-servers.net.
root-servers.net.     3600000 IN  NS      i.root-servers.net.
root-servers.net.     3600000 IN  NS      j.root-servers.net.
root-servers.net.     3600000 IN  NS      k.root-servers.net.
root-servers.net.     3600000 IN  NS      l.root-servers.net.
root-servers.net.     3600000 IN  NS      m.root-servers.net.
a.root-servers.net.   3600000 IN  AAAA    2001:503:ba3e::2:30
a.root-servers.net.   3600000 IN  A       198.41.0.4
b.root-servers.net.   3600000 IN  MX      20 mail.isi.edu.
b.root-servers.net.   3600000 IN  AAAA    2001:500:200::b
b.root-servers.net.   3600000 IN  A       199.9.14.201
c.root-servers.net.   3600000 IN  AAAA    2001:500:2::c
c.root-servers.net.   3600000 IN  A       192.33.4.12
d.root-servers.net.   3600000 IN  AAAA    2001:500:2d::d
d.root-servers.net.   3600000 IN  A       199.7.91.13
e.root-servers.net.   3600000 IN  AAAA    2001:500:a8::e
e.root-servers.net.   3600000 IN  A       192.203.230.10
f.root-servers.net.   3600000 IN  AAAA    2001:500:2f::f
f.root-servers.net.   3600000 IN  A       192.5.5.241
g.root-servers.net.   3600000 IN  AAAA    2001:500:12::d0d
g.root-servers.net.   3600000 IN  A       192.112.36.4
h.root-servers.net.   3600000 IN  AAAA    2001:500:1::53
h.root-servers.net.   3600000 IN  A       198.97.190.53
i.root-servers.net.   3600000 IN  MX      10 mx.i.root-servers.org.
i.root-servers.net.   3600000 IN  AAAA    2001:7fe::53
i.root-servers.net.   3600000 IN  A       192.36.148.17
j.root-servers.net.   3600000 IN  AAAA    2001:503:c27::2:30
j.root-servers.net.   3600000 IN  A       192.58.128.30
k.root-servers.net.   3600000 IN  AAAA    2001:7fd::1
k.root-servers.net.   3600000 IN  A       193.0.14.129
l.root-servers.net.   3600000 IN  AAAA    2001:500:9f::42
l.root-servers.net.   3600000 IN  A       199.7.83.42
m.root-servers.net.   3600000 IN  AAAA    2001:dc3::35
m.root-servers.net.   3600000 IN  A       202.12.27.33
root-servers.net.     3600000 IN  ZONEMD  2018091100 1 1 f1ca0ccd91bd5573d9f431c00ee0101b2545c97602be0a97 8a3b11dbfc1c776d5b3e86ae3d973d6b5349ba7f04340f79
`,
			zonemd: dnstest.New(`root-servers.net.  3600000 IN  ZONEMD  2018091100 1 1 f1ca0ccd91bd5573d9f431c00ee0101b2545c97602be0a97 8a3b11dbfc1c776d5b3e86ae3d973d6b5349ba7f04340f79`).(*dns.ZONEMD),
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
