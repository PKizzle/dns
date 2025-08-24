package dns_test

import (
	"context"
	"sync"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
)

var testXFRData = []dns.RR{
	dnstest.New("miek.nl. IN SOA linode.atoom.net. miek.miek.nl. 2009032802 21600 7200 604800 3600"),
	dnstest.New("x.miek.nl. IN A 10.0.0.1"),
	dnstest.New("miek.nl. IN MX 1 x.miek.nl."),
	dnstest.New("miek.nl. IN SOA linode.atoom.net. miek.miek.nl. 2009032802 21600 7200 604800 3600"),
}

const testXFRZone = "miek.nl."

var sendXFR = func(w dns.ResponseWriter, req *dns.Msg, rrFn func() []dns.RR) {
	var wg sync.WaitGroup
	w.Hijack()
	ch := make(chan *dns.Envelope)
	tr := new(dns.Transfer)
	wg.Add(1)
	go func() {
		tr.Out(w, req, ch)
		wg.Done()
		w.Close()
	}()
	ch <- &dns.Envelope{RR: rrFn()}
	close(ch)
}

func xfrHandler(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
	sendXFR(w, req, func() []dns.RR { return testXFRData })
}

func TestXFRInvalid(t *testing.T) {
	dns.HandleFunc(testXFRZone, func(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
		sendXFR(w, req, func() []dns.RR { return []dns.RR{} })
	})
	defer dns.HandleRemove(testXFRZone)

	s, addr, _ := dnstest.TCPServer(":0")
	defer s.Shutdown(context.TODO())

	tr := new(dns.Transfer)
	m := new(dns.Msg)
	dnsutil.SetAXFR(m, testXFRZone)

	envc, err := tr.In(context.TODO(), m, "tcp", addr)
	if err != nil {
		t.Fatal("failed to zone transfer in", err)
	}

	for env := range envc {
		if env.Error == nil {
			t.Fatalf("failed to catch %s error", dns.ErrSOA)
		}
	}
}

func TestXFR(t *testing.T) {
	dns.HandleFunc(testXFRZone, xfrHandler)
	defer dns.HandleRemove(testXFRZone)

	s, addr, _ := dnstest.TCPServer(":0")
	defer s.Shutdown(context.TODO())
	axfr(t, addr)
}

func TestXFREnvelope(t *testing.T) {
	dns.HandleFunc(testXFRZone, func(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
		var wg sync.WaitGroup
		w.Hijack()
		ch := make(chan *dns.Envelope)
		tr := new(dns.Transfer)
		wg.Add(1)
		go func() {
			tr.Out(w, req, ch)
			w.Close()
			wg.Done()
		}()
		for _, rr := range testXFRData {
			ch <- &dns.Envelope{RR: []dns.RR{rr}}
		}
		close(ch)
	})
	defer dns.HandleRemove(testXFRZone)

	s, addrstr, _ := dnstest.TCPServer(":0")
	defer s.Shutdown(context.TODO())
	axfr(t, addrstr)
}

func axfr(t *testing.T, addr string) {
	tr := new(dns.Transfer)
	m := new(dns.Msg)
	dnsutil.SetAXFR(m, testXFRZone)

	envc, err := tr.In(context.TODO(), m, "tcp", addr)
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

func TestXFRTLS(t *testing.T) {
	dns.HandleFunc(testXFRZone, xfrHandler)
	defer dns.HandleRemove(testXFRZone)

	s, addr, _ := dnstest.TLSServer(":0")
	defer s.Shutdown(context.TODO())

	tr := &dns.Transfer{Transport: dns.NewDefaultTransport()}
	tr.TLSConfig = dnstest.TLSConfig()
	m := new(dns.Msg)
	dnsutil.SetAXFR(m, testXFRZone)

	envc, err := tr.In(context.TODO(), m, "tcp", addr)
	if err != nil {
		t.Fatal("failed to zone transfer in over TLS", err)
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
func axfrTestingSuiteWithCustomTsig(t *testing.T, addrstr string, provider TsigProvider) {
	tr := new(Transfer)
	m := new(Msg)
	var err error
	tr.Conn, err = Dial("tcp", addrstr)
	if err != nil {
		t.Fatal("failed to dial", err)
	}
	tr.TsigProvider = provider
	m.SetAxfr(testXFRZone)
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
	m.SetAxfr(testXFRZone)

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
	HandleFunc(testXFRZone, SingleEnvelopeXfrServer)
	defer HandleRemove(testXFRZone)

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
	HandleFunc(testXFRZone, SingleEnvelopeXfrServer)
	defer HandleRemove(testXFRZone)

	s, addrstr, _, err := RunLocalTCPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	axfrTestingSuiteWithMsgNotSigned(t, addrstr, tsigSecretProvider(tsigSecret))
}


*/
