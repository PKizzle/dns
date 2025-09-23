package dbhost

import (
	"bufio"
	"bytes"
	"io"
	"net"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
	"codeberg.org/miekg/dns/dnsutil"
)

func (d *Dbhost) Load(r io.Reader) {
	data := map[string]dnszone.Node{}

	scanner := bufio.NewScanner(r)
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
			if v6 {
				n, ok := data[
				println(dnsutil.Fqdn(string(f)), "IN", "AAAA", ip.String())
			} else {
				println(dnsutil.Fqdn(string(f)), "IN", "A", ip.String())
			}
			println(dnsutil.ReverseAddr(ip), "IN", "PTR", dnsutil.Fqdn(string(f)))
		}

	}
}
