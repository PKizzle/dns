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
		//{"tcp-tls", "tcp", dnstest.TLSServer}, #broken
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
			if tc.name == "tcp-tls" {
				c.Transport = dns.DefaultTransport
				c.TLSConfig = dnstest.TLSConfig()
			}

			txt := &dns.TXT{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET}}
			m := new(dns.Msg)
			m.Question = []dns.RR{txt}

			m.Pack()

			r, _, err := c.Exchange(context.TODO(), m, tc.network, addrstr)
			if err != nil {
				t.Fatal("failed to exchange miek.nl.", err)
			}
			str := r.Extra[0].(*dns.TXT).Txt[0]
			if str != "Hello world" {
				t.Error("unexpected result for miek.nl.", str, "!= Hello world")
			}

			txt = &dns.TXT{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}
			m.Question = []dns.RR{txt}

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
			txt = &dns.TXT{Hdr: dns.Header{Name: "eXaMPlE.cOm.", Class: dns.ClassINET}}
			m.Question = []dns.RR{txt}

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

// Verify that the server responds to a query with Z flag on, ignoring the flag, and does not echoes it back.
func TestServerZFlag(t *testing.T) {
	dns.HandleFunc("example.com.", HelloHandler)
	s, addrstr, _, err := dnstest.UDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown(context.TODO())

	c := new(dns.Client)
	m := new(dns.Msg)
	txt := &dns.TXT{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET}}
	m.Question = []dns.RR{txt}
	m.Zero = true

	r, _, err := c.Exchange(context.TODO(), m, "udp", addrstr)
	if err != nil {
		t.Fatal("failed to exchange example.com with +zflag", err)
	}
	if r.Zero {
		t.Error("the response should not have Z flag set - even for a query which does")
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Errorf("expected rcode %v, got %v", dns.RcodeSuccess, r.Rcode)
	}
}

// Verify that the server responds to a query with unsupported Opcode with a NotImplemented error and that Opcode is unchanged.
func TestServeNotImplemented(t *testing.T) {
	t.Skip() // TODO:miek fix!
	dns.HandleFunc("example.com.", AnotherHelloHandler)
	opcode := uint8(15)

	s, addrstr, _, err := dnstest.UDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown(context.TODO())

	c := new(dns.Client)
	m := new(dns.Msg)

	// Test that Opcode is like the unchanged from request Opcode and that Rcode is set to NotImplemented
	txt := &dns.TXT{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET}}
	m.Question = []dns.RR{txt}
	m.Opcode = opcode
	r, _, err := c.Exchange(context.TODO(), m, "udp", addrstr)
	if err != nil {
		t.Fatal("failed to exchange example.com with unknown opcode", err)
	}
	if r.Opcode != opcode {
		t.Errorf("expected opcode %v, got %v", opcode, r.Opcode)
	}
	if r.Rcode != dns.RcodeNotImplemented {
		t.Errorf("expected rcode %v, got %v", dns.RcodeNotImplemented, r.Rcode)
	}
}
