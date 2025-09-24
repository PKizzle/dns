package dbhost

import (
	"bufio"
	"bytes"
	"net"
	"os"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
	"codeberg.org/miekg/dns/dnsutil"
)

func (d *Dbhost) Load() error {
	f, err := os.Open(d.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	data := map[string]dnszone.Node{}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if i := bytes.Index(line, []byte{'#'}); i >= 0 {
			// discard comments
			line = line[0:i]
		}
		fs := bytes.Fields(line)
		if len(fs) < 2 {
			continue
		}

		// make into RRs and put then in a dnszone.Node
		v6 := bytes.Index(fs[0], []byte{':'}) > -1
		ip := net.ParseIP(string(fs[0]))
		for _, f := range fs[1:] {
			key := dnsutil.Canonical(string(f))
			n, ok := data[key]
			if !ok {
				n = dnszone.Node{Name: key}
			}
			if v6 {
				n.RRs = append(n.RRs, &dns.AAAA{Hdr: dns.Header{Name: key, Class: dns.ClassINET, TTL: d.ttl}, AAAA: ip})
			} else {
				n.RRs = append(n.RRs, &dns.A{Hdr: dns.Header{Name: key, Class: dns.ClassINET, TTL: d.ttl}, A: ip})
			}
			data[key] = n

			rev := dnsutil.Canonical(dnsutil.ReverseAddr(ip))
			n, ok = data[rev]
			if !ok {
				n = dnszone.Node{Name: rev}
			}
			n.RRs = append(n.RRs, &dns.PTR{Hdr: dns.Header{Name: rev, Class: dns.ClassINET, TTL: d.ttl}, Ptr: dnsutil.Fqdn(string(f))})
			data[rev] = n
		}
	}

	d.Lock()
	d.Data = data
	d.Unlock()
	return nil
}
