package dbhost

import (
	"bufio"
	"bytes"
	"io"
	"net"

	"codeberg.org/miekg/dns/dnsutil"
)

func (d *Dbhost) Load(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Bytes()
		if i := bytes.Index(line, []byte{'#'}); i >= 0 {
			// discard comments
			line = line[0:i]
		}
		f := bytes.Fields(line)
		if len(f) < 2 {
			continue
		}

		v6 := bytes.Index(f[0], []byte{':'}) > -1
		ip := net.ParseIP(string(f[0]))
		if v6 {
			println(string(f[0]), "IN", "AAAA", string(f[1]))
		} else {
			println(string(f[0]), "IN", "A", string(f[1]))
		}
		println(dnsutil.ReverseAddr(ip))
	}
}
