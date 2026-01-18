package dnszone

import (
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

type mockZone struct {
	data   map[string]*Node
	origin string
}

func (m *mockZone) Load() error { return nil }
func (m *mockZone) Get(s string) (*Node, bool) {
	n, ok := m.data[s]
	return n, ok
}
func (m *mockZone) Previous(s string) *Node { return nil } // Not needed for basic exact match/wildcard
func (m *mockZone) Set(n *Node) string {
	m.data[n.Name] = n
	return ""
}
func (m *mockZone) Apex() *Node {
	if n, ok := m.data[m.origin]; ok {
		return n
	}
	return &Node{Name: m.origin}
}
func (m *mockZone) Origin() string            { return m.origin }
func (m *mockZone) Labels() int               { return 0 } // Mock
func (m *mockZone) Walk(f func(*Node) bool)   {}
func (m *mockZone) AuthoritativeWalk(f func(*Node, bool) bool) {}

func TestRetrieveCloning(t *testing.T) {
	origin := "example.org."
	z := &mockZone{
		data:   make(map[string]*Node),
		origin: origin,
	}

	// 1. Setup Exact Match
	exactName := "www.example.org."
	addr, _ := netip.ParseAddr("127.0.0.1")
	aRecord := &dns.A{
		Hdr: dns.Header{Name: exactName, Class: dns.ClassINET, TTL: 3600},
		A:   rdata.A{Addr: addr},
	}
	exactNode := &Node{
		Name: exactName,
		RRs:  []dns.RR{aRecord},
	}
	z.Set(exactNode)

	// 2. Setup Wildcard Match
	wildName := "*.example.org."
	txtRecord := &dns.TXT{
		Hdr: dns.Header{Name: wildName, Class: dns.ClassINET, TTL: 3600},
		TXT: rdata.TXT{Txt: []string{"wild"}},
	}
	wildNode := &Node{
		Name: wildName,
		RRs:  []dns.RR{txtRecord},
	}
	z.Set(wildNode)

	// Test Exact Match (Should share pointer)
	req := new(dns.Msg)
	q := new(dns.A)
	q.Hdr.Name = exactName
	q.Hdr.Class = dns.ClassINET
	// q.Hdr.Rrtype determined by type
	req.Question = []dns.RR{q}

	resp := Retrieve(z, req, nil)
	if len(resp.Answer) != 1 {
		t.Fatalf("Expected 1 answer for exact match, got %d", len(resp.Answer))
	}

	// Compare pointers
	gotRR := resp.Answer[0]
	if gotRR != aRecord {
		t.Errorf("Expected exact match to return original RR pointer (no clone), but got different pointer. Optimization failed.")
	}

	// Test Wildcard Match (Should be cloned)
	qname := "foo.example.org."
	req = new(dns.Msg)
	qTxt := new(dns.TXT)
	qTxt.Hdr.Name = qname
	qTxt.Hdr.Class = dns.ClassINET
	req.Question = []dns.RR{qTxt}

	resp = Retrieve(z, req, nil)
	if len(resp.Answer) != 1 {
		t.Fatalf("Expected 1 answer for wildcard match, got %d", len(resp.Answer))
	}

	gotRR = resp.Answer[0]
	if gotRR == txtRecord {
		t.Errorf("Expected wildcard match to return CLONED RR pointer, but got original pointer. Synthesize corrupted zone data?")
	}
	if gotRR.Header().Name != qname {
		t.Errorf("Expected wildcard answer name to be %s, got %s", qname, gotRR.Header().Name)
	}
	if txtRecord.Header().Name != wildName {
		t.Errorf("Original wildcard record name modified! Zone corrupted! Got %s", txtRecord.Header().Name)
	}
}
