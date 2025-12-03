package template_test

import (
	"context"
	"regexp"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/atomtest"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/template"
	"codeberg.org/miekg/dns/dnstest"
)

func TestTemplate(t *testing.T) {
	h := &template.Template{Path: "testdata/msg.go.tmpl", Regexp: regexp.MustCompile(".*")}

	r := dns.NewMsg("www.example.org.", dns.TypeA)
	r.Pack()

	w := dnstest.NewRecorder(&dnstest.ResponseWriter{})
	h.HandlerFunc(atomtest.Noop).ServeDNS(context.TODO(), w, r)

	if w.Msg.ID != r.ID {
		t.Fatalf("expected %d, got %d", r.ID, w.Msg.ID)
	}
	if len(w.Msg.Answer) != 1 {
		t.Fatalf("expected answer section of %d, got %d", 1, len(w.Msg.Answer))
	}
}
