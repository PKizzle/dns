package dnshttp

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func TestDOH(t *testing.T) {
	testcases := map[string]struct {
		method string
		url    string
	}{
		"POST request HTTPS":       {method: http.MethodPost, url: "https://example.org:443"},
		"POST request HTTP":        {method: http.MethodPost, url: "http://example.org:443"},
		"POST request no protocol": {method: http.MethodPost, url: "example.org:443"},
		"GET request HTTPS":        {method: http.MethodGet, url: "https://example.org:443"},
		"GET request HTTP":         {method: http.MethodGet, url: "http://example.org"},
		"GET request no protocol":  {method: http.MethodGet, url: "example.org:443"},
	}

	MsgAcceptFunc = func(m *dns.Msg) dns.MsgAcceptAction { return dns.MsgAccept }

	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			m := new(dns.Msg)
			dnsutil.SetQuestion(m, "example.org.", dns.TypeDNSKEY)

			req, err := NewRequest(tc.method, tc.url, m)
			if err != nil {
				t.Fatalf("failure to make request: %s", err)
			}

			m1, err := Request(req)
			if err != nil {
				t.Fatalf("failure to get message from request: %s", err)
			}

			if x := m1.Question[0].Header().Name; x != "example.org." {
				t.Errorf("qname expected %s, got %s", "example.org.", x)
			}
			if x, ok := m1.Question[0].(*dns.DNSKEY); !ok {
				t.Errorf("qtype expected %T, got %T", &dns.DNSKEY{}, x)
			}
		})
	}
}

func TestDOHRFC8484(t *testing.T) {
	// https://datatracker.ietf.org/doc/html/rfc8484#section-4.1.1
	testcases := []struct {
		method string
		url    string
		header http.Header
		body   []byte
	}{
		{
			method: http.MethodGet,
			url:    "https://example.com/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB",
			header: http.Header{
				"Accept": {MimeType},
			},
		},
		{
			method: http.MethodPost,
			url:    "https://example.com/dns-query",
			header: http.Header{
				"Accept":       {MimeType},
				"Content-Type": {MimeType},
			},
			body: []byte{
				0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
				0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
				0x01,
			},
		},
		{
			method: http.MethodGet,
			url:    "https://example.com/dns-query?dns=AAABAAABAAAAAAAAAWE-NjJjaGFyYWN0ZXJsYWJlbC1tYWtlcy1iYXNlNjR1cmwtZGlzdGluY3QtZnJvbS1zdGFuZGFyZC1iYXNlNjQHZXhhbXBsZQNjb20AAAEAAQ",
			header: http.Header{
				"Accept": {MimeType},
			},
		},
	}

	for i, tc := range testcases {
		t.Run(fmt.Sprintf("Request/%d", i), func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.url, bytes.NewReader(tc.body))
			maps.Copy(req.Header, tc.header)

			m, err := Request(req)
			if err != nil {
				t.Fatalf("failure to get message from request: %s", err)
			}

			if x := m.Question[0].Header().Name; !strings.HasSuffix(x, "example.com.") {
				t.Errorf("expected %q to end with %q", x, "example.com.")
			}

			u := url.URL{
				Scheme: req.URL.Scheme,
				Host:   req.URL.Host,
			}
			dr, err := NewRequest(tc.method, u.String(), m)
			if err != nil {
				t.Fatalf("failure to get request from message: %s", err)
			}

			if x := dr.URL.String(); x != tc.url {
				t.Errorf("expected %q, got %q", tc.url, x)
			}
			for k, v := range tc.header {
				if !reflect.DeepEqual(dr.Header.Values(k), v) {
					t.Errorf("expected header %q: %q to be %q", k, dr.Header, v)
				}
			}
			if tc.body != nil {
				body, _ := io.ReadAll(dr.Body)
				if !bytes.Equal(body, tc.body) {
					t.Errorf("expected %q, got %q", tc.body, body)
				}
			}
		})
	}

	t.Run("Response", func(t *testing.T) {
		// https://datatracker.ietf.org/doc/html/rfc8484#section-4.2.2
		w := httptest.NewRecorder()
		maps.Copy(w.Header(), http.Header{
			"Content-Type":   {MimeType},
			"Content-Length": {"61"},
			"Cache-Control":  {"max-age=3709"},
		})
		w.Write([]byte{
			0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
			0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00,
			0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x7d, 0x00, 0x10, 0x20, 0x01, 0x0d,
			0xb8, 0xab, 0xcd, 0x00, 0x12, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
		})

		m, err := Response(w.Result())
		if err != nil {
			t.Fatalf("failure to get message from response: %s", err)
		}

		if x := m.Answer[0].Header().Name; x != "www.example.com." {
			t.Errorf("expected %s, got %s", "www.example.com.", x)
		}
		ip := netip.MustParseAddr("2001:db8:abcd:12:1:2:3:4")
		if x := m.Answer[0].(*dns.AAAA).Addr; x != ip {
			t.Errorf("expected %s, got %s", ip, x)
		}
	})
}
