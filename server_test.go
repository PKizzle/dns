package dns_test

import (
	"context"
	"io"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
)

func TestServer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		network string
		run     func(laddr string, opts ...func(*dns.Server)) (*dns.Server, string, chan error, error)
	}{
		{"udp", "udp", dnstest.UDPServer},
		{"tcp", "tcp", dnstest.TCPServer},
		{"PacketConn", "udp", dnstest.PacketConnServer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dns.HandleFunc("miek.nl.", HelloHandler)
			dns.HandleFunc("example.com.", AnotherHelloHandler)

			s, addrstr, _, err := tc.run(":0")
			if err != nil {
				t.Fatalf("unable to run test server: %v", err)
			}
			defer s.Shutdown(context.TODO())

			c := &dns.Client{}
			txt := &dns.TXT{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET}}
			m := new(dns.Msg)
			m.Question = []dns.RR{txt}

			m.Pack()

			r, _, err := c.Exchange(context.TODO(), m, tc.network, addrstr)
			if err != nil || len(r.Extra) == 0 {
				t.Fatal("failed to exchange miek.nl", err)
			}
			str := r.Extra[0].(*dns.TXT).Txt[0]
			if str != "Hello world" {
				t.Error("unexpected result for miek.nl", str, "!= Hello world")
			}

			txt = &dns.TXT{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}
			m.Question = []dns.RR{txt}

			m.Pack()

			r, _, err = c.Exchange(context.TODO(), m, tc.network, addrstr)
			if err != nil {
				t.Fatal("failed to exchange example.com", err)
			}
			str = r.Extra[0].(*dns.TXT).Txt[0]
			if str != "Hello example" {
				t.Error("unexpected result for example.com", str, "!= Hello example")
			}

			// Test Mixes cased as noticed by Ask.
			txt = &dns.TXT{Hdr: dns.Header{Name: "eXaMPlE.cOm.", Class: dns.ClassINET}}
			m.Question = []dns.RR{txt}

			m.Pack()

			r, _, err = c.Exchange(context.TODO(), m, tc.network, addrstr)
			if err != nil {
				t.Error("failed to exchange eXaMplE.cOm", err)
			}
			str = r.Extra[0].(*dns.TXT).Txt[0]
			if str != "Hello example" {
				t.Error("unexpected result for example.com", str, "!= Hello example")
			}
		})
	}
}

func HelloHandler(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	dnsutil.SetReply(m, req)
	m.Extra = []dns.RR{&dns.TXT{Hdr: dns.Header{Name: m.Question[0].Header().Name, Class: dns.ClassINET}, Txt: []string{"Hello world"}}}
	m.Pack()
	io.Copy(w, m)
}

func AnotherHelloHandler(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	dnsutil.SetReply(m, req)
	m.Extra = []dns.RR{&dns.TXT{Hdr: dns.Header{Name: m.Question[0].Header().Name, Class: dns.ClassINET}, Txt: []string{"Hello example"}}}
	m.Pack()
	io.Copy(w, m)
}
