package svcb

import (
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// This tests everything valid about SVCB but parsing.
// Parsing tests belong to parse_test.go.
func TestSVCB(t *testing.T) {
	svcbs := []struct {
		key  string
		data string
	}{
		{`mandatory`, `alpn,key65000`},
		{`alpn`, `h2,h2c`},
		{`port`, `499`},
		{`ipv4hint`, `3.4.3.2,1.1.1.1`},
		{`no-default-alpn`, ``},
		{`ipv6hint`, `1::4:4:4:4,1::3:3:3:3`},
		{`ech`, `YUdWc2JHOD0=`},
		{`dohpath`, `/dns-query{?dns}`},
		{`ohttp`, ``},
		{`key65000`, `4\ 3`},
		{`key65001`, `\"\ `},
		{`key65002`, ``},
		{`key65003`, `=\"\"`},
		{`key65004`, `\254\ \ \030\000`},
	}

	for _, o := range svcbs {
		keyCode := StringToKey(o.key)
		pairFn := KeyToPair(keyCode)
		if pairFn == nil {
			t.Error("failed to lookup svc key: ", o.key)
			continue
		}
		pair := pairFn()
		if PairToKey(pair) != keyCode {
			t.Error("key constant is not in sync: ", keyCode)
			continue
		}
		err := Parse(pair, o.data, "")
		if err != nil {
			t.Error("failed to parse svc pair: ", o.key)
			continue
		}

		b := make([]byte, pair.Len())
		off, err := _pack(pair, b, 0)
		if err != nil {
			t.Error("failed to pack value of svc pair: ", o.key, err)
			continue
		}
		if pair.Len() != off {
			t.Errorf("expected packed svc value %s to be of length %d but got %d", o.key, pair.Len(), off)
		}

		if str := pair.String(); str != o.data {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", o.key, o.data, str)
		}

		sc := cryptobyte.String(b[4:]) // skip the TLV
		err = _unpack(pair, &sc)
		if err != nil {
			t.Error("failed to unpack value of svc pair: ", o.key, err)
		}
	}
}

func TestALPNPresentation(t *testing.T) {
	tests := map[string]string{
		"h2":                "h2",
		"http":              "http",
		"\xfa":              `\250`,
		"some\"other,chars": `some\"other\\\044chars`,
	}
	for input, want := range tests {
		e := new(ALPN)
		e.Alpn = []string{input}
		if e.String() != want {
			t.Errorf("improper conversion with String(), wanted %v got %v", want, e.String())
		}
	}
}

/*
func TestALPN(t *testing.T) {
	tests := map[string][]string{
		`. 1 IN SVCB 10 one.test. alpn=h2`:                                         {"h2"},
		`. 2 IN SVCB 20 two.test. alpn=h2,h3-19`:                                   {"h2", "h3-19"},
		`. 3 IN SVCB 30 three.test. alpn="f\\\\oo\\,bar,h2"`:                       {`f\oo,bar`, "h2"},
		`. 4 IN SVCB 40 four.test. alpn="part1,part2,part3\\,part4\\\\"`:           {"part1", "part2", `part3,part4\`},
		`. 5 IN SVCB 50 five.test. alpn=part1\,\p\a\r\t2\044part3\092,part4\092\\`: {"part1", "part2", `part3,part4\`},
	}
	for s, v := range tests {
		rr, err := dns.New(s)
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
