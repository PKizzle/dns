package dns_test

import (
	"context"
	"sync"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
)

var testTransferData = []dns.RR{
	dnstest.New("miek.nl. IN SOA linode.atoom.net. miek.miek.nl. 2009032802 21600 7200 604800 3600"),
	dnstest.New("x.miek.nl. IN A 10.0.0.1"),
	dnstest.New("miek.nl. IN MX 1 x.miek.nl."),
	dnstest.New("miek.nl. IN SOA linode.atoom.net. miek.miek.nl. 2009032800 21600 7200 604800 3600"),
}

const testTransferZone = "miek.nl."

func TestTransferInvalid(t *testing.T) {
	dns.HandleFunc(testTransferZone, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		r.Unpack()
		w.Hijack()

		env := make(chan *dns.Envelope)
		c := new(dns.Client)

		var wg sync.WaitGroup
		wg.Go(func() {
			c.TransferOut(w, r, env)
		})
		env <- &dns.Envelope{Answer: []dns.RR{}}
		close(env)
		w.Close()
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
		if e.Error == nil {
			t.Errorf("expected error, got none")
		}
	}
}

func TestTransfer(t *testing.T) {
	dns.HandleFunc(testTransferZone, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		r.Unpack()
		w.Hijack()

		env := make(chan *dns.Envelope)
		c := dns.NewClient()

		var wg sync.WaitGroup
		wg.Go(func() {
			err := c.TransferOut(w, r, env)
			if err != nil {
				t.Fatal(err)
			}
			w.Close()
		})
		env <- &dns.Envelope{Answer: []dns.RR{testTransferData[0]}}
		env <- &dns.Envelope{Answer: []dns.RR{testTransferData[1]}}
		env <- &dns.Envelope{Answer: []dns.RR{testTransferData[2]}}
		env <- &dns.Envelope{Answer: []dns.RR{testTransferData[3]}}
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
					t.Errorf("unexpected error: %s", e.Error)
					break
				}
				i += len(e.Answer)
			}
			if i != len(testTransferData) {
				t.Fatalf("bad axfr: expected %d, got %d", i, len(testTransferData))
			}
		})
	}
}

func TestTransferTSIG(t *testing.T) {
	dns.HandleFunc(testTransferZone, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		r.Unpack()
		w.Hijack()

		var wg sync.WaitGroup
		env := make(chan *dns.Envelope)
		c := dns.NewClient()
		c.TSIGSigner = dns.HmacTSIG{[]byte("geheim")}
		wg.Go(func() {
			err := c.TransferOut(w, r, env)
			if err != nil {
				t.Fatal(err)
			}
			w.Close()
		})
		env <- &dns.Envelope{Answer: []dns.RR{testTransferData[0]}}
		env <- &dns.Envelope{Answer: []dns.RR{testTransferData[1]}}
		env <- &dns.Envelope{Answer: []dns.RR{testTransferData[2]}}
		env <- &dns.Envelope{Answer: []dns.RR{testTransferData[3]}}
		close(env)
	})
	defer dns.HandleRemove(testTransferZone)

	cancel, addr, _ := dnstest.TCPServer(":0")
	defer cancel()

	c := dns.NewClient()
	c.TSIGSigner = dns.HmacTSIG{[]byte("geheim")}

	m := dns.NewMsg(testTransferZone, dns.TypeAXFR)
	m.Pseudo = []dns.RR{dns.NewTSIG(".", dns.HmacSHA512, 0)}

	env, err := c.TransferIn(context.TODO(), m, "tcp", addr)
	if err != nil {
		t.Fatal("failed to zone transfer in", err)
	}

	for e := range env {
		if e.Error != nil {
			t.Fatal(e.Error)
		}
	}
}

/*
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

*/
