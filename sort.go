package dns

import (
	"sort"
)

// Compare returns an integer comparing two RRs according to "Canonical Form and Order of Resource Records" in
// RFC 4034 Section 6. Note the TTL is skipped when comparing.
// The result will be 0 if a == b, -1 if a < b, and +1 if a > b.
func Compare(a, b RR) int {
	x := CompareName(a.Header().Name, b.Header().Name)
	if x != 0 {
		return x
	}

	at := RRToType(a)
	bt := RRToType(b)

	if at < bt {
		return -1
	}
	if at > bt {
		return +1
	}

	if a.Header().Class < b.Header().Class {
		return -1
	}
	if a.Header().Class > b.Header().Class {
		return 1
	}

	return compare(a, b)
}

var _ sort.Interface = RRset{}

func (set RRset) Len() int           { return len(set) }
func (set RRset) Less(i, j int) bool { return Compare(set[i], set[j]) == -1 }
func (set RRset) Swap(i, j int)      { set[i], set[j] = set[j], set[i] }

// See https://bert-hubert.blogspot.com/2015/10/how-to-do-fast-canonical-ordering-of.html
func CompareName(a, b string) int {
	labels := 1

	lasta, _ := dnsutilPrev(a, 0)
	lastb, _ := dnsutilPrev(b, 0)

	for {
		cura, overshota := dnsutilPrev(a, labels)
		curb, overshotb := dnsutilPrev(b, labels)
		if overshota && overshotb {
			return 0
		}
		if overshota {
			return -1
		}
		if overshotb {
			return 1
		}

		x := compareLabel(a[cura:lasta], b[curb:lastb])
		if x != 0 {
			return x
		}
		labels++
		lasta = cura
		lastb = curb
	}
}

// Equal returns true if a and b are equal. See [Compare].
func Equal(a, b RR) bool { return Compare(a, b) == 0 }

// EqualName returns true if the domain names a and b are equal. See [CompareName].
func EqualName(a, b string) bool { return CompareName(a, b) == 0 }
