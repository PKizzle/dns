package dnsutil

import (
	"bytes"
	"net"
	"testing"
)

func TestAddrReverse(t *testing.T) {
	testcases := []struct {
		reverse string
		addr    net.IP
	}{
		{"54.119.58.176.in-addr.arpa.", net.ParseIP("176.58.119.54").To4()},
		{".58.176.in-addr.arpa.", nil},
		{"b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.in-addr.arpa.", nil},
		{"b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", net.ParseIP("2001:db8::567:89ab")},
		{"d.0.1.0.0.2.ip6.arpa.", nil},
		{"54.119.58.176.ip6.arpa.", nil},
		{"NONAME", nil},
		{"", nil},
	}
	for i, tc := range testcases {
		got := AddrReverse(tc.reverse)
		if !bytes.Equal(got, tc.addr) {
			t.Errorf("Test %d, expected '%s', got '%s'", i, tc.addr, got)
		}
	}
}
