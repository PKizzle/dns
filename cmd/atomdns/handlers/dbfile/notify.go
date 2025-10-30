package dbfile

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
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

func (d *Dbfile) HandlerFuncNotify(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	if !slices.Contains(d.From.IPs, dnsutil.RemoteIP(w)) {
		return // ignore request
	}
	m := new(dns.Msg)
	dnsutil.SetReply(m, r)
	m.Authoritative = true
	m.Data = r.Data
	m.Pack()
	io.Copy(w, m)

	z := d.Zone(dns.Zone(ctx))
	apex := z.Apex()
	serial := uint32(0)
	for _, rr := range apex.RRs {
		if s, ok := rr.(*dns.SOA); ok {
			serial = s.Serial
			break
		}
	}
	if !d.From.AvailableFrom(z.Origin(), serial) {
		log.With(slog.Uint64("serial", uint64(serial))).Warn("Notify seen, but no newer zone available", "zone", z.Origin())
		return
	}

	d.TransferIn(dns.Zone(ctx)) // TODO(miek): error handling
}

// Notify will send notifies to all configured to IP addresses.
func (t *Transfer) Notify(origin string) error {
	if len(t.IPs) == 0 {
		return nil
	}

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
	alog := log.With("upstream", strings.Join(t.IPs, ","), "zone", origin)
	alog.Debug("Sent notifies")
	return lasterr
}

func notify(c *dns.Client, m *dns.Msg, ip string, sources []string) error {
	c.Dialer.LocalAddr = &net.UDPAddr{IP: source(ip, sources)}
	for range 2 {
		alog := log.With("upstream", ip, "zone", m.Question[0].Header().Name)
		r, _, err := c.Exchange(context.TODO(), m, "udp", ip)
		if err != nil {
			alog.Error("Failed to sent notify", Err(err))
			time.Sleep(time.Second)
			continue
		}
		if r.Rcode == dns.RcodeSuccess {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("upstream %q did not accept our notify for zone %q", ip, m.Question[0].Header().Name)
}

// returns the correct family address or nil, or nil when nothing is needed.
func source(ip string, sources []string) net.IP {
	h, _, _ := net.SplitHostPort(ip)
	fam := net.ParseIP(h).To4() != nil
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

// AvailableFrom return true if the "other side" has a newer SOA then we have. The first IP that answers
// with a higher serial is enough to return true.
func (t *Transfer) AvailableFrom(origin string, serial uint32) bool {
	c := dns.NewClient()
	m := dns.NewMsg(origin, dns.TypeSOA)

	for _, ip := range t.IPs {
		alog := log.With("upstream", ip, "zone", origin)
		m, _, err := c.Exchange(context.TODO(), m, "tcp", ip)
		if err != nil {
			alog.Error("Upstream did not accept our query", Err(err))
			continue
		}
		if err == nil {
			for _, rr := range m.Answer {
				if s, ok := rr.(*dns.SOA); ok {
					if dns.CompareSerial(serial, s.Serial) == -1 {
						alog.Debug("Upstream serial is higher than ours", "serial", serial, "upstream-serial", s.Serial)
						return true
					}
				}
			}
		}
	}
	return false
}
