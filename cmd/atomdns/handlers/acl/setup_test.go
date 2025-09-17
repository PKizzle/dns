package acl

import (
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	testcases := []struct {
		name   string
		config string
		exp    bool
	}{
		{
			"blocklist",
			`acl {
				block type A net 192.168.0.0/16
			}`,
			false,
		},
		{
			"blocklist",
			`acl {
				block type * net 192.168.0.0/16
			}`,
			false,
		},
		{
			"blocklist",
			`acl {
				block type A net *
			}`,
			false,
		},
		{
			"blocklist",
			`acl {
				allow type * net 192.168.1.0/24
				block type * net 192.168.0.0/16
			}`,
			false,
		},
		{
			"filter",
			`acl {
				filter type A net 192.168.0.0/16
			}`,
			false,
		},
		{
			"allowlist",
			`acl {
				allow type * net 192.168.0.0/16
				block type * net *
			}`,
			false,
		},
		{
			"drop 1",
			`acl {
				drop type * net 192.168.0.0/16
			}`,
			false,
		},
		{
			"fine-grained 1",
			`acl a.example.org {
				block type * net 192.168.1.0/24
			}`,
			false,
		},
		{
			"fine-grained 2",
			`acl a.example.org {
				block type * net 192.168.1.0/24
			}
			acl b.example.org {
				block type * net 192.168.2.0/24
			}`,
			false,
		},
		{
			"multiple networks 1",
			`acl example.org {
				block type * net 192.168.1.0/24 192.168.3.0/24
			}`,
			false,
		},
		{
			"multiple qtypes 1",
			`acl example.org {
				block type TXT ANY CNAME net 192.168.3.0/24
			}`,
			false,
		},
		{
			"missing argument 1",
			`acl {
				block A net 192.168.0.0/16
			}`,
			true,
		},
		{
			"missing argument 2",
			`acl {
				block type net 192.168.0.0/16
			}`,
			true,
		},
		{
			"illegal argument 1",
			`acl {
				block type ABC net 192.168.0.0/16
			}`,
			true,
		},
		{
			"illegal argument 2",
			`acl {
				blck type A net 192.168.0.0/16
			}`,
			true,
		},
		{
			"illegal argument 3",
			`acl {
				block type A net 192.168.0/16
			}`,
			true,
		},
		{
			"illegal argument 4",
			`acl {
				block type A net 192.168.0.0/33
			}`,
			true,
		},
		{
			"blocklist IPv6",
			`acl {
				block type A net 2001:0db8:85a3:0000:0000:8a2e:0370:7334
			}`,
			false,
		},
		{
			"blocklist IPv6",
			`acl {
				block type * net 2001:db8:85a3::8a2e:370:7334
			}`,
			false,
		},
		{
			"blocklist IPv6",
			`acl {
				block type A
			}`,
			false,
		},
		{
			"blocklist IPv6",
			`acl {
				allow net 2001:db8:abcd:0012::0/64
				block net 2001:db8:abcd:0012::0/48
			}`,
			false,
		},
		{
			"filter 1 IPv6",
			`acl {
				filter type A net 2001:0db8:85a3:0000:0000:8a2e:0370:7334
			}`,
			false,
		},
		{
			"whitelist 1 IPv6",
			`acl {
				allow net 2001:db8:abcd:0012::0/64
				block
			}`,
			false,
		},
		{
			"drop 1 IPv6",
			`acl {
				drop net 2001:db8:abcd:0012::0/64
			}`,
			false,
		},
		{
			"fine-grained 1 IPv6",
			`acl a.example.org {
				block net 2001:db8:abcd:0012::0/64
			}`,
			false,
		},
		{
			"fine-grained 2 IPv6",
			`acl a.example.org {
				block net 2001:db8:abcd:0012::0/64
			}
			acl b.example.org {
				block net 2001:db8:abcd:0013::0/64
			}`,
			false,
		},
		{
			"multiple networks 1 IPv6",
			`acl example.org {
				block net 2001:db8:abcd:0012::0/64 2001:db8:85a3::8a2e:370:7334/64
			}`,
			false,
		},
		{
			"illegal argument 1 IPv6",
			`acl {
				block type A net 2001::85a3::8a2e:370:7334
			}`,
			true,
		},
		{
			"illegal argument 2 IPv6",
			`acl {
				block type A net 2001:db8:85a3:::8a2e:370:7334
			}`,
			true,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			acl := new(Acl)
			co := dnsserver.NewTestController(tc.config)
			err := acl.Setup(co)
			if (err != nil) != tc.exp {
				t.Errorf("expected %t, got %t", tc.exp, err)
			}
		})
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		name string
		args string
		want string
	}{
		{
			"range",
			"10.218.10.8/24",
			"10.218.10.8/24",
		},
		{
			"IPv4",
			"10.218.10.8",
			"10.218.10.8/32",
		},
		{
			"IPv6",
			"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			"2001:0db8:85a3:0000:0000:8a2e:0370:7334/128",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalize(tt.args); got != tt.want {
				t.Errorf("expected %s, got %s", tt.want, got)
			}
		})
	}
}
