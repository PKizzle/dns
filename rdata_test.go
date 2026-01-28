package dns_test

import (
	"fmt"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// Example on how get the text presentation of an [dns.RR].
func ExampleRDATA_string() {
	rr := &dns.MX{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET, TTL: 3600}, MX: rdata.MX{Preference: 10, Mx: "mx.miek.nl."}}
	s := rr.Header().String() + " " + dnsutil.TypeToString(dns.RRToType(rr)) + "\t" + rr.Data().String()
	fmt.Println(s)
	// Output: miek.nl.	3600	IN MX	10 mx.miek.nl.
}
