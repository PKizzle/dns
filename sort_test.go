package dns

import (
	"fmt"
	"slices"
	"sort"
	"testing"

	"codeberg.org/miekg/dns/rdata"
)

type name []string

func (n name) Len() int           { return len(n) }
func (n name) Swap(i, j int)      { n[i], n[j] = n[j], n[i] }
func (n name) Less(i, j int) bool { return CompareName(n[i], n[j]) == -1 }

func TestSort(t *testing.T) {
	testcases := []struct {
		name     string
		unsorted name
		sorted   name
	}{
		{
			"powerdns",
			name{"aaa.powerdns.de.", "bbb.powerdns.net.", "xxx.powerdns.com."},
			name{"xxx.powerdns.com.", "aaa.powerdns.de.", "bbb.powerdns.net."},
		},
		{
			"rfc4034",
			name{"example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.", "zABC.a.EXAMPLE.", "z.example.", "*.z.example."},
			name{"example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.", "zABC.a.EXAMPLE.", "z.example.", "*.z.example."},
		},
		{
			"rfc4034-ddd",
			name{"example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.", "zABC.a.EXAMPLE.", "z.example.", "\001.z.example.", "*.z.example.", "\200.z.example."},
			name{"example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.", "zABC.a.EXAMPLE.", "z.example.", "\001.z.example.", "*.z.example.", "\200.z.example."},
		},
		{
			"root",
			name{".", "nl."},
			name{".", "nl."},
		},
		{
			"dash",
			name{"dns-ext.nic.cr.", "dns.nic.cr."},
			name{"dns.nic.cr.", "dns-ext.nic.cr."},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			sort.Sort(tc.unsorted)
			for i := range len(tc.unsorted) {
				if tc.unsorted[i] != tc.sorted[i] {
					t.Fatalf("expected %v, got %v", tc.sorted, tc.unsorted)
				}
			}
		})
	}
}

func TestSortRRset(t *testing.T) {
	testcases := []struct {
		name     string
		unsorted RRset
		sorted   RRset
	}{
		{
			"miekns",
			RRset([]RR{
				&NS{Hdr: Header{Name: "miek.nl.", Class: ClassINET, TTL: 600}, NS: rdata.NS{Ns: "linode.atoom.net."}},
				&NS{Hdr: Header{Name: "miek.nl.", Class: ClassINET, TTL: 600}, NS: rdata.NS{Ns: "omval.tednet.nl"}},
				&NS{Hdr: Header{Name: "miek.nl.", Class: ClassINET, TTL: 600}, NS: rdata.NS{Ns: "ns-ext.nlnetlabs.nl."}},
			}),
			RRset([]RR{
				&NS{Hdr: Header{Name: "miek.nl.", Class: ClassINET, TTL: 600}, NS: rdata.NS{Ns: "omval.tednet.nl"}},
				&NS{Hdr: Header{Name: "miek.nl.", Class: ClassINET, TTL: 600}, NS: rdata.NS{Ns: "linode.atoom.net."}},
				&NS{Hdr: Header{Name: "miek.nl.", Class: ClassINET, TTL: 600}, NS: rdata.NS{Ns: "ns-ext.nlnetlabs.nl."}},
			}),
		},
		{
			"zwns",
			RRset([]RR{
				&NS{Hdr: Header{Name: "zw.", Class: ClassINET, TTL: 172800}, NS: rdata.NS{Ns: "zw-ns.anycast.pch.net."}},
				&NS{Hdr: Header{Name: "zw.", Class: ClassINET, TTL: 172800}, NS: rdata.NS{Ns: "ns1zim.telone.co.zw."}},
				&NS{Hdr: Header{Name: "zw.", Class: ClassINET, TTL: 172800}, NS: rdata.NS{Ns: "ns2zim.telone.co.zw."}},
				&NS{Hdr: Header{Name: "zw.", Class: ClassINET, TTL: 172800}, NS: rdata.NS{Ns: "ns1.liquidtelecom.net."}},
				&NS{Hdr: Header{Name: "zw.", Class: ClassINET, TTL: 172800}, NS: rdata.NS{Ns: "ns2.liquidtelecom.net."}},
			}),
			RRset([]RR{
				&NS{Hdr: Header{Name: "zw.", Class: ClassINET, TTL: 172800}, NS: rdata.NS{Ns: "ns1.liquidtelecom.net."}},
				&NS{Hdr: Header{Name: "zw.", Class: ClassINET, TTL: 172800}, NS: rdata.NS{Ns: "ns2.liquidtelecom.net."}},
				&NS{Hdr: Header{Name: "zw.", Class: ClassINET, TTL: 172800}, NS: rdata.NS{Ns: "zw-ns.anycast.pch.net."}},
				&NS{Hdr: Header{Name: "zw.", Class: ClassINET, TTL: 172800}, NS: rdata.NS{Ns: "ns1zim.telone.co.zw."}},
				&NS{Hdr: Header{Name: "zw.", Class: ClassINET, TTL: 172800}, NS: rdata.NS{Ns: "ns2zim.telone.co.zw."}},
			}),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			sort.Sort(tc.unsorted)
			// check rdata only
			for i := range len(tc.unsorted) {
				switch tc.unsorted[i].(type) {
				case *NS:
					if tc.unsorted[i].(*NS).Ns != tc.sorted[i].(*NS).Ns {
						t.Fatalf("expected %s, got %s", tc.sorted[i].(*NS).Ns, tc.unsorted[i].(*NS).Ns)
					}
				}
			}
		})
	}
}

func TestCompareSerial(t *testing.T) {
	testcases := []struct {
		name string
		a, b uint32
		want int
	}{
		{"equal", 100, 100, 0},
		{"a-less", 100, 200, -1},
		{"a-greater", 200, 100, 1},
		// 4200000000 is numerically > 2009032802 but diff (2190967198) > 2^31: a is behind.
		{"rfc1982-a-behind", 4200000000, 2009032802, -1},
		// inverse: 2009032802 has wrapped past 4200000000, so it is ahead.
		{"rfc1982-a-ahead", 2009032802, 4200000000, 1},
		// diff exactly 2^31-1 = MaxSerialIncrement: a < b (old code incorrectly returned 1).
		{"boundary-a-less", 1000000000, 1000000000 + MaxSerialIncrement, -1},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CompareSerial(tc.a, tc.b); got != tc.want {
				t.Fatalf("expected serial %d, got %d", tc.want, got)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	testcases := []struct {
		name string
		a    RR
		b    RR
		ok   bool
	}{
		{
			"ok:aaaa",
			dnstestNew("a.example.org.  IN AAAA    2a01:7e00::f03c:91ff:fef1:6735"),
			dnstestNew("a.example.org.  IN AAAA    2a01:7e00::f03c:91ff:fef1:6735"),
			true,
		},
		{
			"diff:aaaa",
			dnstestNew("a.example.org.  IN AAAA    2a01:7e00::f03c:91ff:fef1:6735"),
			dnstestNew("a.example.org.  IN AAAA    3a01:7e00::f03c:91ff:fef1:6735"),
			false,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := Equal(tc.a, tc.b)
			if got != tc.ok {
				t.Fatalf("expected %t, got %t for %q == %q", tc.ok, got, tc.a, tc.b)
			}
		})
	}
}

func TestEqualName(t *testing.T) {
	testcases := []struct {
		a   string
		b   string
		exp bool
	}{
		{"example.org.", "example.org.", true},
		{"example.org.", "eXAMPLe.oRG.", true},
	}
	for i, tc := range testcases {
		got := EqualName(tc.a, tc.b)
		if got != tc.exp {
			t.Errorf("test %d, expected %t, got %t for %s, %s", i, tc.exp, got, tc.a, tc.b)
		}
	}
}

func ExampleRRset_sort() {
	rrs := RRset([]RR{
		func() RR { rr, _ := New("miek.nl. IN NS linode.atoom.net."); return rr }(),
		func() RR { rr, _ := New("miek.nl. IN NS omval.tednet.nl."); return rr }(),
		func() RR { rr, _ := New("miek.nl. IN NS ns-ext.nlnetlabs.nl."); return rr }(),
	})
	sort.Sort(rrs)
	for i := range rrs {
		fmt.Println(rrs[i])
	}
}

func ExampleRRset_compact() {
	rrs := RRset([]RR{
		func() RR { rr, _ := New("miek.nl. IN NS linode.atoom.net."); return rr }(),
		func() RR { rr, _ := New("miek.nl. IN NS omval.tednet.nl."); return rr }(),
		func() RR { rr, _ := New("miek.nl. IN NS omval.tednet.nl."); return rr }(),
		func() RR { rr, _ := New("miek.nl. IN NS ns-ext.nlnetlabs.nl."); return rr }(),
	})
	sort.Sort(rrs)
	rrs = slices.CompactFunc(rrs, func(a, b RR) bool { return Equal(a, b) })
	for i := range rrs {
		fmt.Println(rrs[i])
	}
}
