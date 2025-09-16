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
	for range 3 {
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

// Available return true if the "other side" has a new SOA then we have. The first IP that answers
// with a higher serial is enough to return true.
func (t *Transfer) Available(origin string, serial uint32) bool {
	c := dns.NewClient()
	m := dns.NewMsg(origin, dns.TypeSOA)

	for _, ip := range t.IPs {
		m, _, err := c.Exchange(context.TODO(), m, "tcp", net.JoinHostPort(ip, "53"))
		if err == nil {
			for _, rr := range m.Answer {
				if s, ok := rr.(*dns.SOA); ok {
					if dns.CompareSerial(serial, s.Serial) == -1 {
						// ours is smaller then the remote, transfer
						return true
					}
				}
			}
		}
	}
	return false
}
