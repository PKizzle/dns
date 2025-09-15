package dbfile

import (
	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Transfer holds all the information to perform in incoming or outgoing zone transfer.
// The families from IP, Notifies and Sources will be matched upon sending the actual notifies.
type Transfer struct {
	IPs []string

	TSIG       *dns.TSIG
	TSIGSecret string // base64

	Notifies []string
	Sources  []string
}

// Notify will send notifies to all configured TO IP addresses.
func (t *Transfer) Notify(origin string) error {
	m := new(dns.Msg)
	m.Authoritative = true
	m.Opcode = dns.OpcodeNotify
	dnsutil.SetQuestion(m, origin, dns.TypeSOA)
	c := new(dns.Client)
	// add tsig if needed

	var lasterr error
	for _, ip := range t.IPs {
		if err := notify(c, m, ip, t.Sources); err != nil {
			lasterr = err
		}
	}
	log.Debug("Sent notifies for zone %q to %v", origin, t.IPs)
	return lasterr
}

func notify(c *dns.Client, m *dns.Msg, to string, sources []string) error {
	return nil
}

/*
func sendNotify(c *dns.Client, m *dns.Msg, s string, sources []net.IP) error {
	var err error

	code := dns.RcodeServerFailure
	for i := 0; i < 3; i++ {
		ret := &dns.Msg{}
		switch len(sources) {
		case 0:
			ret, _, err = c.Exchange(m, s)
		default:
			source := sourceForFamily(s, sources)
			if source == nil {
				ret, _, err = c.Exchange(m, s)
			} else {
				conn, err := connWithSrcAddr(s, source)
				if err != nil {
					log.Warningf("Can not use %s as notifiy source: %s", source, err)
					break
				}
				ret, _, err = c.ExchangeWithConn(m, conn) // nolint:all
			}
		}
		if err != nil {
			log.Warningf("Failed to sent notify: %s", err)
			continue
		}
		// due to all the skipping when encountering errors, ret may be nil
		if ret != nil {
			code = ret.Rcode
		} else {
			err = fmt.Errorf("notify for zone %q got no reply", m.Question[0].Name)
		}
		if code == dns.RcodeSuccess {
			return nil
		}
	}
	if err != nil {
		return fmt.Errorf("notify for zone %q was not accepted by %q: %q", m.Question[0].Name, s, err)
	}
	return fmt.Errorf("notify for zone %q was not accepted by %q: rcode was %q", m.Question[0].Name, s, dnsutil.RcodeToString(code))
}

func sourceForFamily(s string, sources []net.IP) net.IP {
	s1, _, _ := net.SplitHostPort(s) // this must work
	sfam := net.ParseIP(s1).To4() != nil
	if sfam { // v4
		for _, s2 := range sources {
			if s2.To4() != nil {
				return s2
			}
		}
	} else { // v6
		for _, s2 := range sources {
			if s2.To4() == nil {
				return s2
			}
		}
	}
	return nil
}

	dialer := &net.Dialer{
		LocalAddr: &net.UDPAddr{
			IP:   source,
			Port: 0,
		},
	}
*/
