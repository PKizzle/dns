package dbfile

import (
	"context"
	"fmt"
	"net"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Transfer holds all the information to perform in incoming or outgoing zone transfer.
// The families from IPs, notifies and sources will be matched upon sending the actual notifies.
type Transfer struct {
	IPs []string

	TSIG       *dns.TSIG
	TSIGSecret string // base64

	Notifies []string
	Sources  []string
}

// IsNotify checks if the received notify is from any of the configured from IP addreses.
func (t *Transfer) IsNotify(w dns.ResponseWriter) bool {
	// valid from ip
	for _, ip := range t.IPs {
		if ip == dnsutil.RemoteIP(w) {
			return true
		}
	}
	return false
}

// Notify will send notifies to all configured to IP addresses.
func (t *Transfer) Notify(origin string) error {
	m := new(dns.Msg)
	m.Authoritative = true
	m.Opcode = dns.OpcodeNotify
	dnsutil.SetQuestion(m, origin, dns.TypeSOA)
	c := new(dns.Client)
	c.Transport = dns.NewDefaultTransport()
	// TODO(miek): TSIG

	var lasterr error
	for _, ip := range t.IPs {
		if err := notify(c, m, ip, t.Sources); err != nil {
			lasterr = err
		}
	}
	log.Debug(fmt.Sprintf("Sent notifies for zone %q to %v", origin, t.IPs))
	return lasterr
}

func notify(c *dns.Client, m *dns.Msg, ip string, sources []string) error {
	c.Dialer.LocalAddr = &net.UDPAddr{IP: source(ip, sources)}
	for i := 0; i < 3; i++ {
		r, _, err := c.Exchange(context.TODO(), m, "udp", ip)
		if err != nil {
			log.Error(fmt.Sprintf("Failed to sent notify: %s", err))
			time.Sleep(time.Second)
			continue
		}
		if r.Rcode == dns.RcodeSuccess {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("notify for zone %q was not accepted by %q", m.Question[0].Header().Name, ip)
}

// returns the correct family address or nil, or nil when nothing is needed.
func source(ip string, sources []string) net.IP {
	fam := net.ParseIP(ip).To4() != nil
	for _, s := range sources {
		sip := net.ParseIP(s)
		if sip.To4() != nil && fam {
			return sip
		}
		if sip.To4() == nil && !fam {
			return sip
		}
	}
	return nil
}
