package dns

import (
	"sort"
	"testing"
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
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			sort.Sort(tc.unsorted)
			for i := range len(tc.unsorted) {
				if tc.unsorted[i] != tc.sorted[i] {
					t.Fatalf("expected %s, got %s", tc.sorted[i], tc.unsorted[i])
				}
			}
		})
	}
}

func TestSortRRset(t *testing.T) {
	// TODO: add more
	testcases := []struct {
		name     string
		unsorted RRset
		sorted   RRset
	}{
		{
			"miekns",
			RRset([]RR{
				&NS{Hdr: Header{Name: "miek.nl.", Class: ClassINET, TTL: 600}, Ns: "linode.atoom.net."},
				&NS{Hdr: Header{Name: "miek.nl.", Class: ClassINET, TTL: 600}, Ns: "omval.tednet.nl"},
				&NS{Hdr: Header{Name: "miek.nl.", Class: ClassINET, TTL: 600}, Ns: "ns-ext.nlnetlabs.nl."},
			}),
			RRset([]RR{
				&NS{Hdr: Header{Name: "miek.nl.", Class: ClassINET, TTL: 600}, Ns: "omval.tednet.nl"},
				&NS{Hdr: Header{Name: "miek.nl.", Class: ClassINET, TTL: 600}, Ns: "linode.atoom.net."},
				&NS{Hdr: Header{Name: "miek.nl.", Class: ClassINET, TTL: 600}, Ns: "ns-ext.nlnetlabs.nl."},
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

func TestCompare(t *testing.T) {
	testcases := []struct {
		name string
		a    RR
		b    RR
		ok   bool
	}{
		{
			"ok:aaaa",
			func() RR { rr, _ := New("a.example.org.  IN AAAA    2a01:7e00::f03c:91ff:fef1:6735"); return rr }(),
			func() RR { rr, _ := New("a.example.org.  IN AAAA    2a01:7e00::f03c:91ff:fef1:6735"); return rr }(),
			true,
		},
		{
			"diff:aaaa",
			func() RR { rr, _ := New("a.example.org.  IN AAAA    2a01:7e00::f03c:91ff:fef1:6735"); return rr }(),
			func() RR { rr, _ := New("a.example.org.  IN AAAA    3a01:7e00::f03c:91ff:fef1:6735"); return rr }(),
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
