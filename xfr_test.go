package dns_test

import (
	"context"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
)

var testXFRData = []dns.RR{
	dnstest.New("miek.nl.	0	IN	SOA	linode.atoom.net. miek.miek.nl. 2009032802 21600 7200 604800 3600"),
	dnstest.New("x.miek.nl.	1792	IN	A	10.0.0.1"),
	dnstest.New("miek.nl.	1800	IN	MX	1	x.miek.nl."),
}

const testXFRZone = "miek.nl."

func invalidXFRHandler(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
	ch := make(chan *dns.Envelope)
	tr := new(dns.Transfer)

	go func() {
		tr.Out(w, req, ch)
		w.Close()
	}()
	ch <- &dns.Envelope{RR: []dns.RR{}}
	close(ch)
	w.Hijack()
}

func singleEnvelopeXFRHandler(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
	ch := make(chan *dns.Envelope)
	tr := new(dns.Transfer)

	go tr.Out(w, req, ch)
	ch <- &dns.Envelope{RR: testXFRData}
	close(ch)
	w.Hijack()
}

func multipleEnvelopeXFRHandler(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
	ch := make(chan *dns.Envelope)
	tr := new(dns.Transfer)

	go tr.Out(w, req, ch)

	for _, rr := range testXFRData {
		ch <- &dns.Envelope{RR: []dns.RR{rr}}
	}
	close(ch)
	w.Hijack()
}

func TestXFRInvalid(t *testing.T) {
	dns.HandleFunc(testXFRZone, invalidXFRHandler)
	defer dns.HandleRemove(testXFRZone)

	s, addrstr, _ := dnstest.TCPServer(":0")
	defer s.Shutdown(context.TODO())

	tr := new(dns.Transfer)
	m := new(dns.Msg)
	dnsutil.SetAXFR(m, testXFRZone)

	envc, err := tr.In(context.TODO(), m, "tcp", addrstr)
	if err != nil {
		t.Fatal("failed to zone transfer in", err)
	}

	for env := range envc {
		if env.Error == nil {
			t.Fatal("failed to catch 'no SOA' error")
		}
	}
}

func TestXFRSingleEnvelope(t *testing.T) {
	dns.HandleFunc(testXFRZone, singleEnvelopeXFRHandler)
	defer dns.HandleRemove(testXFRZone)

	s, addrstr, err := dnstest.TCPServer(":0", func(srv *dns.Server) {
		// setup tsig
	})
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown(context.TODO())
	axfr(t, addrstr)
}

/*
func TestSingleEnvelopeXfrTLS(t *testing.T) {
	HandleFunc("miek.nl.", SingleEnvelopeXfrServer)
	defer HandleRemove("miek.nl.")

	cert, err := tls.X509KeyPair(CertPEMBlock, KeyPEMBlock)
	if err != nil {
		t.Fatalf("unable to build certificate: %v", err)
	}

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	s, addrstr, _, err := RunLocalTLSServer(":0", &tlsConfig)
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	axfrTestingSuiteTLS(t, addrstr)
}

func TestMultiEnvelopeXfr(t *testing.T) {
	HandleFunc("miek.nl.", MultipleEnvelopeXfrServer)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalTCPServer(":0", func(srv *Server) {
		srv.TsigSecret = tsigSecret
	})
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	axfrTestingSuite(t, addrstr)
}
*/

func axfr(t *testing.T, addrstr string) {
	tr := new(dns.Transfer)
	m := new(dns.Msg)
	dnsutil.SetAXFR(m, testXFRZone)

	envc, err := tr.In(context.TODO(), m, "tcp", addrstr)
	if err != nil {
		t.Fatal("failed to zone transfer in", err)
	}

	i := 0
	for env := range envc {
		if env.Error != nil {
			t.Fatal(env.Error)
		}
		i += len(env.RR)
	}
	if i != len(testXFRData) {
		t.Fatalf("bad axfr: expected %d, got %d", i, len(testXFRData))
	}
}

/*

func axfrTestingSuiteTLS(t *testing.T, addrstr string) {
	tr := new(Transfer)
	m := new(Msg)
	m.SetAxfr("miek.nl.")

	tr.TLS = &tls.Config{
		InsecureSkipVerify: true,
	}
	c, err := tr.In(m, addrstr)
	if err != nil {
		t.Fatal("failed to zone transfer in", err)
	}

	var records []RR
	for msg := range c {
		if msg.Error != nil {
			t.Fatal(msg.Error)
		}
		records = append(records, msg.RR...)
	}

	if len(records) != len(xfrTestData) {
		t.Fatalf("bad axfr: expected %v, got %v", records, xfrTestData)
	}

	for i, rr := range records {
		if !IsDuplicate(rr, xfrTestData[i]) {
			t.Fatalf("bad axfr: expected %v, got %v", records, xfrTestData)
		}
	}
}

func axfrTestingSuiteWithCustomTsig(t *testing.T, addrstr string, provider TsigProvider) {
	tr := new(Transfer)
	m := new(Msg)
	var err error
	tr.Conn, err = Dial("tcp", addrstr)
	if err != nil {
		t.Fatal("failed to dial", err)
	}
	tr.TsigProvider = provider
	m.SetAxfr("miek.nl.")
	m.SetTsig("axfr.", HmacSHA256, 300, time.Now().Unix())

	c, err := tr.In(m, addrstr)
	if err != nil {
		t.Fatal("failed to zone transfer in", err)
	}

	var records []RR
	for msg := range c {
		if msg.Error != nil {
			t.Fatal(msg.Error)
		}
		records = append(records, msg.RR...)
	}

	if len(records) != len(xfrTestData) {
		t.Fatalf("bad axfr: expected %v, got %v", records, xfrTestData)
	}

	for i, rr := range records {
		if !IsDuplicate(rr, xfrTestData[i]) {
			t.Errorf("bad axfr: expected %v, got %v", records, xfrTestData)
		}
	}
}

func axfrTestingSuiteWithMsgNotSigned(t *testing.T, addrstr string, provider TsigProvider) {
	tr := new(Transfer)
	m := new(Msg)
	var err error
	tr.Conn, err = Dial("tcp", addrstr)
	if err != nil {
		t.Fatal("failed to dial", err)
	}
	tr.TsigProvider = provider
	m.SetAxfr("miek.nl.")

	c, err := tr.In(m, addrstr)
	if err != nil {
		t.Fatal("failed to zone transfer in", err)
	}

	for msg := range c {
		if !errors.Is(msg.Error, ErrNoSig) {
			t.Fatal("expecting ErrNoSig error")
		}
	}
}

func TestCustomTsigProvider(t *testing.T) {
	HandleFunc("miek.nl.", SingleEnvelopeXfrServer)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalTCPServer(":0", func(srv *Server) {
		srv.TsigProvider = tsigSecretProvider(tsigSecret)
	})
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	axfrTestingSuiteWithCustomTsig(t, addrstr, tsigSecretProvider(tsigSecret))
}

func TestTSIGNotSigned(t *testing.T) {
	HandleFunc("miek.nl.", SingleEnvelopeXfrServer)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalTCPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	axfrTestingSuiteWithMsgNotSigned(t, addrstr, tsigSecretProvider(tsigSecret))
}
*/
