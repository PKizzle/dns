package dns

import (
	"context"
	"fmt"
	"testing"
)

func TestClientExternal(t *testing.T) {
	m := &Msg{MsgHeader: MsgHeader{ID: ID(), RecursionDesired: true}}
	mx := &MX{Hdr: Header{Name: "miek.nl.", Class: ClassINET}}
	m.Question = []RR{mx}

	nsid := &NSID{}
	m.Pseudo = []RR{nsid}
	err := m.Pack()
	t.Logf("%v\n", m.Data)
	if err != nil {
		t.Fatalf("failed to pack: %s", err)
	}

	c := &Client{}
	r, _, err := c.Exchange(context.Background(), m, "udp", "8.8.8.8:53")
	if err != nil {
		t.Errorf("%s", err)
	}
	fmt.Println(r.String())
	t.Logf("%v\n", r.Data)
}

func TestTransferInExternal(t *testing.T) {
	c := NewClient()
	secret, _ := fromBase64([]byte("Vn37JPSCmaCHKJhghcpRg8m6PlQ="))
	c.TSIGSigner = HmacTSIG{Secret: secret}

	m := NewMsg("ok.bad-dnssec.wb.sidnlabs.nl.", TypeAXFR)
	m.Pseudo = []RR{NewTSIG("wb_sha1.", HmacSHA1, 0)}

	env, err := c.TransferIn(context.TODO(), m, "tcp", "94.198.159.39:53")
	if err != nil {
		t.Fatal("failed to zone transfer in", err)
	}

	for e := range env {
		if e.Error != nil {
			t.Fatal(e.Error)
		}
		for i := range e.Answer {
			fmt.Printf("%s\n", e.Answer[i])
		}
	}
}

func TestTransferInExternalRoot(t *testing.T) {
	c := NewClient()

	m := NewMsg(".", TypeAXFR)

	env, err := c.TransferIn(context.TODO(), m, "tcp", "192.33.4.12:53")
	if err != nil {
		t.Fatal("failed to zone transfer in", err)
	}

	j := 0
	for e := range env {
		if e.Error != nil {
			t.Fatal(e.Error)
		}
		for i := range e.Answer {
			fmt.Printf("%s\n", e.Answer[i])
		}
		j++
	}
	fmt.Printf("%d envelopes\n", j)
}
