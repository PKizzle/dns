package dns

import (
	"fmt"
	"testing"
	"time"

	"codeberg.org/miekg/dns/deleg"
	"codeberg.org/miekg/dns/internal/dnsfuzz"
	"codeberg.org/miekg/dns/svcb"
)

func TestNew(t *testing.T) {
	testcases := []struct {
		name string
		in   string
		fn   func(RR) error
	}{
		{
			"SVCB/ALPN", `. 1 IN SVCB 10 one.test. alpn=h2`,
			func(rr RR) error {
				alpn := rr.(*SVCB).Value[0].(*svcb.ALPN).Alpn
				if alpn[0] != "h2" {
					return fmt.Errorf("parsing alpn failed, wanted %v got %v", "h2", alpn)
				}
				return nil
			},
		},
		{
			"SVCB/ALPN", `. 2 IN SVCB 20 two.test. alpn=h2,h3-19`,
			func(rr RR) error {
				v := []string{"h2", "h3-19"}
				alpn := rr.(*SVCB).Value[0].(*svcb.ALPN).Alpn
				for i := range v {
					if v[i] != alpn[i] {
						return fmt.Errorf("parsing alpn failed, wanted %v got %v", v, alpn)
					}
				}
				return nil
			},
		},
		{
			"SVCB/ALPN", `. 5 IN SVCB 50 five.test. alpn=part1\,\p\a\r\t2\044part3\092,part4\092\\`,
			func(rr RR) error {
				v := []string{"part1", "part2", `part3,part4\`}
				alpn := rr.(*SVCB).Value[0].(*svcb.ALPN).Alpn
				for i := range v {
					if v[i] != alpn[i] {
						return fmt.Errorf("parsing alpn failed, wanted %v got %v", v, alpn)
					}
				}
				return nil
			},
		},
		{
			"DSYNC", `child._dsync.example. IN DSYNC CDS NOTIFY 5300 rr-endpoint.example.`,
			func(rr RR) error {
				dsync := rr.(*DSYNC)
				if dsync.Scheme != 1 {
					return fmt.Errorf("parsing DSYNC failed, expected scheme 1, got %d", dsync.Scheme)
				}
				if dsync.Port != 5300 {
					return fmt.Errorf("parsing DSYNC failed, expected port 5300, got %d", dsync.Port)
				}
				if dsync.Target != "rr-endpoint.example." {
					return fmt.Errorf("parsing DSYNC failed, expected port rr-endpoint.example., got %s", "rr-endpoint.example.")
				}
				return nil
			},
		},
		{
			"DELEG", "example.org. IN DELEG server-ipv4=192.0.2.1 server-ipv6=2001:DB8::1",
			func(rr RR) error {
				dlg := rr.(*DELEG)
				v0 := dlg.DELEG.Value[0]
				v1 := dlg.DELEG.Value[1]
				_ = v0.(*deleg.SERVERIPV4)
				_ = v1.(*deleg.SERVERIPV6)
				return nil
			},
		},
		{
			"DELEG", `example.org. IN DELEG server-ipv4="192.0.2.1" server-ipv6="2001:DB8::1"`,
			func(rr RR) error {
				dlg := rr.(*DELEG)
				v0 := dlg.DELEG.Value[0]
				v1 := dlg.DELEG.Value[1]
				_ = v0.(*deleg.SERVERIPV4)
				_ = v1.(*deleg.SERVERIPV6)
				return nil
			},
		},
		// EDNS0 types
		{
			"NSID", `. IN NSID 5573652074686520666f726365: "Use the force"`, func(rr RR) error { _ = rr.(*NSID); return nil },
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			rr, err := New(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if err = tc.fn(rr); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func FuzzNew(f *testing.F) {
	f.Add(`. 5 IN SVCB 50 five.test. alpn=part1\,\p\a\r\t2\044part3\092,part4\092\\`)
	f.Add(`miek.nl. IN 3600 MX 15 mx.miek.nl.`)
	start := time.Now()
	f.Fuzz(func(t *testing.T, s string) {
		New(s)
		dnsfuzz.Stop(t, start)
	})
}

/*
func TestALPN(t *testing.T) {
	tests := map[string][]string{
		`. 2 IN SVCB 20 two.test. alpn=h2,h3-19`:                                   {"h2", "h3-19"},
		`. 3 IN SVCB 30 three.test. alpn="f\\\\oo\\,bar,h2"`:                       {`f\oo,bar`, "h2"},
		`. 4 IN SVCB 40 four.test. alpn="part1,part2,part3\\,part4\\\\"`:           {"part1", "part2", `part3,part4\`},
	}
	for s, v := range tests {
		if err != nil {
			t.Error("failed to parse RR: ", err)
			continue
		}
		alpn := rr.(*dns.SVCB).Value[0].(*svcb.ALPN).Alpn
		if len(v) != len(alpn) {
			t.Fatalf("parsing alpn failed, wanted %v got %v", v, alpn)
		}
		for i := range v {
			if v[i] != alpn[i] {
				t.Fatalf("parsing alpn failed, wanted %v got %v", v, alpn)
			}
		}
	}
}
*/
