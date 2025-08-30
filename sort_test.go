package dns

import (
	"sort"
	"testing"
)

type name []string

func (n name) Len() int           { return len(n) }
func (n name) Swap(i, j int)      { n[i], n[j] = n[j], n[i] }
func (n name) Less(i, j int) bool { return CompareName(n[i], n[j]) == -1 }

func TestCompareName(t *testing.T) {
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
