package dns_test

import (
	"context"
	"io"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
)

func HelloHandler(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	dnsutil.SetReply(m, req)
	m.Extra = []dns.RR{&dns.TXT{Hdr: dns.Header{Name: m.Question[0].Header().Name, Class: dns.ClassINET}, Txt: []string{"Hello world"}}}
	io.Copy(w, m)
}

func AnotherHelloHandler(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	dnsutil.SetReply(m, req)
	m.Extra = []dns.RR{&dns.TXT{Hdr: dns.Header{Name: m.Question[0].Header().Name, Class: dns.ClassINET}, Txt: []string{"Hello example"}}}
	io.Copy(w, m)
}

func TestServer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		network string
		run     func(laddr string, opts ...func(*dns.Server)) (*dns.Server, string, chan error, error)
	}{
		{"udp", "udp", dnstest.UDPServer},
		{"tcp", "tcp", dnstest.TCPServer},
		{"tcp-tls", "tcp", dnstest.TLSServer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dns.HandleFunc("miek.nl.", HelloHandler)
			dns.HandleFunc("example.com.", AnotherHelloHandler)

			s, addrstr, _, err := tc.run(":0")
			defer s.Shutdown(context.TODO())

			c := &dns.Client{}
			if tc.name == "tcp-tls" {
				c.TLSConfig = dnstest.TLSConfig()
			}

			m := new(dns.Msg)
			dnsutil.SetQuestion(m, "miek.nl.", dns.TypeTXT)
			m.Pack()

			r, _, err := c.Exchange(context.TODO(), m, tc.network, addrstr)
			if err != nil {
				t.Fatal("failed to exchange miek.nl.", err)
			}
			str := r.Extra[0].(*dns.TXT).Txt[0]
			if str != "Hello world" {
				t.Error("unexpected result for miek.nl.", str, "!= Hello world")
			}

			dnsutil.SetQuestion(m, "example.com.", dns.TypeTXT)
			m.Pack()

			r, _, err = c.Exchange(context.TODO(), m, tc.network, addrstr)
			if err != nil {
				t.Fatal("failed to exchange example.com.", err)
			}
			str = r.Extra[0].(*dns.TXT).Txt[0]
			if str != "Hello example" {
				t.Error("unexpected result for example.com.", str, "!= Hello example")
			}

			// Test Mixes cased as noticed by Ask.
			dnsutil.SetQuestion(m, "eXaMPlE.cOm.", dns.TypeTXT)
			m.Pack()

			r, _, err = c.Exchange(context.TODO(), m, tc.network, addrstr)
			if err != nil {
				t.Error("failed to exchange eXaMplE.cOm.", err)
			}
			str = r.Extra[0].(*dns.TXT).Txt[0]
			if str != "Hello example" {
				t.Error("unexpected result for example.com.", str, "!= Hello example")
			}
		})
	}
}

// Verify that the server responds to a query with Z flag on, ignoring the flag, and does not echoes it back.
func TestServerZFlag(t *testing.T) {
	dns.HandleFunc("example.com.", HelloHandler)
	s, addrstr, _, _ := dnstest.UDPServer(":0")
	defer s.Shutdown(context.TODO())

	m := new(dns.Msg)
	dnsutil.SetQuestion(m, "example.com.", dns.TypeTXT)
	m.Zero = true
	m.Pack()

	r, err := dns.Exchange(context.TODO(), m, "udp", addrstr)
	if err != nil {
		t.Fatal("failed to exchange example.com. with +zflag", err)
	}
	if r.Zero {
		t.Error("the response should not have Z flag set - even for a query which does")
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Errorf("expected rcode %v, got %v", dns.RcodeSuccess, r.Rcode)
	}
}
