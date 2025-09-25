package dns

import (
	"fmt"
	"testing"

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
				if "h2" != alpn[0] {
					fmt.Errorf("parsing alpn failed, wanted %v got %v", "h2", alpn)
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
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			rr, _ := New(tc.in)
			err := tc.fn(rr)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
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
