package dns_test

import (
	"context"
	"log"
	"sync"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/internal/bin"
)

var testTransferData = []dns.RR{
	dnstest.New("miek.nl. IN SOA linode.atoom.net. miek.miek.nl. 2009032802 21600 7200 604800 3600"),
	dnstest.New("x.miek.nl. IN A 10.0.0.1"),
	dnstest.New("miek.nl. IN MX 1 x.miek.nl."),
	dnstest.New("miek.nl. IN SOA linode.atoom.net. miek.miek.nl. 2009032802 21600 7200 604800 3600"),
}

const testTransferZone = "miek.nl."

func TestTransferInvalid(t *testing.T) {
	dns.HandleFunc(testTransferZone, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		var wg sync.WaitGroup
		w.Hijack()
		env := make(chan *dns.Envelope)
		c := new(dns.Client)
		wg.Go(func() {
			c.TransferOut(w, env)
			w.Close()
		})
		env <- &dns.Envelope{Msg: &dns.Msg{}}
		close(env)
	})
	defer dns.HandleRemove(testTransferZone)

	cancel, addr, _ := dnstest.TCPServer(":0")
	defer cancel()

	c := new(dns.Client)
	m := new(dns.Msg)
	dnsutil.SetQuestion(m, testTransferZone, dns.TypeAXFR)

	env, err := c.TransferIn(context.TODO(), m, "tcp", addr)
	if err != nil {
		t.Fatal("failed to zone transfer in", err)
	}

	for e := range env {
		e.Msg.Unpack()
		if len(e.Answer) != 0 {
			t.Errorf("expected empty answer, got %d", len(e.Answer))
		}
		if len(e.Answer) > 0 {
			if _, ok := m.Answer[0].(*dns.SOA); ok {
				t.Errorf("expected no SOA, got one")
			}
		}
	}
}

func TestTransfer(t *testing.T) {
	dns.HandleFunc(testTransferZone, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		var wg sync.WaitGroup
		w.Hijack()
		env := make(chan *dns.Envelope)
		c := new(dns.Client)

		wg.Go(func() {
			c.TransferOut(w, env)
			w.Close()
		})

		m := &dns.Msg{Data: r.Data}
		dnsutil.SetReply(m, r)
		m.Answer = testTransferData
		m.Pack()

		env <- &dns.Envelope{Msg: m}
		close(env)
	})
	defer dns.HandleRemove(testTransferZone)

	for _, name := range []string{"tcp", "tcp-tls"} {
		t.Run(name, func(t *testing.T) {
			addr := ""
			switch name {
			case "tcp":
				cancel, adr, _ := dnstest.TCPServer(":0")
				defer cancel()
				addr = adr
			case "tcp-tls":
				cancel, adr, _ := dnstest.TLSServer(":0")
				defer cancel()
				addr = adr
			}

			c := dns.NewClient()
			if name == "tcp-tls" {
				c.TLSConfig = dnstest.TLSConfig()
			}

			m := dns.NewMsg(testTransferZone, dns.TypeAXFR)

			env, err := c.TransferIn(context.TODO(), m, "tcp", addr)
			if err != nil {
				t.Fatal("failed to setup zone transfer in", err)
			}

			i := 0
			for e := range env {
				if e.Error != nil {
					t.Fatal(e.Error)
				}
				e.Msg.Unpack()
				i += len(e.Msg.Answer)
			}
			if i != len(testTransferData) {
				t.Fatalf("bad axfr: expected %d, got %d", i, len(testTransferData))
			}
		})
	}
}

func TestTransferTSIG(t *testing.T) {
	dns.HandleFunc(testTransferZone, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		var wg sync.WaitGroup
		w.Hijack()
		env := make(chan *dns.Envelope)
		c := new(dns.Client)
		wg.Go(func() {
			c.TransferOut(w, env)
			w.Close()
		})

		r.Unpack()
		println("REAVIED", r.String())
		println(bin.Dump(r.Data))
		o := dns.TSIGOption{}
		v := dns.TSIGHMAC{"geheim"}
		err := dns.TSIGVerify(r, v, &o)
		if err != nil {
			log.Fatal(err)
		}

		// send multiple so we need to do this, if there is tsig needed.
		// send replies back with tsig record and sign with original request mac.

		env <- &dns.Envelope{Msg: &dns.Msg{}}
		close(env)
	})
	defer dns.HandleRemove(testTransferZone)

	cancel, addr, _ := dnstest.TCPServer(":0")
	defer cancel()

	c := new(dns.Client)
	m := dns.NewMsg(testTransferZone, dns.TypeAXFR)
	m.Pseudo = []dns.RR{dns.NewTSIG("keyname.", dns.HmacSHA512, 0)}

	s := dns.TSIGHMAC{"geheim"}
	err := dns.TSIGSign(m, s, &dns.TSIGOption{})
	if err != nil {
		t.Fatal(err)
	}
	println("SIGNED", m.String())
	println(bin.Dump(m.Data))

	env, err := c.TransferIn(context.TODO(), m, "tcp", addr)
	if err != nil {
		t.Fatal("failed to zone transfer in", err)
	}

	for e := range env {
		e.Msg.Unpack()
		if len(e.Answer) != 0 {
			t.Errorf("expected empty answer, got %d", len(e.Answer))
		}
		if len(e.Answer) > 0 {
			if _, ok := m.Answer[0].(*dns.SOA); ok {
				t.Errorf("expected no SOA, got one")
			}
		}
		// Verify the answer, with request mac.
	}
}

/*
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
	m.SetAxfr(testTransferZone)
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
	m.SetAxfr(testTransferZone)

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
	HandleFunc(testTransferZone, SingleEnvelopeXfrServer)
	defer HandleRemove(testTransferZone)

	cancel, addrstr, _, err := RunLocalTCPServer(":0", func(srv *Server) {
		srv.TsigProvider = tsigSecretProvider(tsigSecret)
	})
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	axfrTestingSuiteWithCustomTsig(t, addrstr, tsigSecretProvider(tsigSecret))
}

func TestTSIGNotSigned(t *testing.T) {
	HandleFunc(testTransferZone, SingleEnvelopeXfrServer)
	defer HandleRemove(testTransferZone)

	s, addrstr, _, err := RunLocalTCPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	axfrTestingSuiteWithMsgNotSigned(t, addrstr, tsigSecretProvider(tsigSecret))
}


*/
