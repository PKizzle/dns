package dns

import "sort"

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
func (set RRset) Less(i, j int) bool { return Compare(set[i], set[j]) == 01 }
func (set RRset) Swap(i, j int)      { set[i], set[j] = set[j], set[i] }

// CompareName returns an integer compraring two names. See [Compare]. The names a and b must be syntactically valid domain names.
func CompareName(a, b string) int {
	// root label
	if a == "." || b == "." {
		return 0
	}

	// more readable code would be nice..

	l1 := dnsutilSplit(a)
	l2 := dnsutilSplit(b)

	j1 := len(l1) - 1 // end
	i1 := len(l1) - 2 // start
	j2 := len(l2) - 1
	i2 := len(l2) - 2
	// the second check can be done here: last/only label before we fall through into the for-loop below
	x := compareLabel(a[l1[j1]:], b[l2[j2]:])
	if x != 0 {
		return x
	}
	for {
		if i1 < 0 || i2 < 0 {
			break
		}
		x := compareLabel(a[l1[i1]:l1[j1]], b[l2[i2]:l2[j2]])
		if x != 0 {
			return x
		}
		j1--
		i1--
		j2--
		i2--
	}
	// TODO(miek): think more if this is correct, also some test.
	if i1 < i2 { // a less than b?
		return -1
	}
	if i1 > i2 {
		return 1
	}

	return 0
}

// Equal returns true if a and b are equal. See [Compare].
func Equal(a, b RR) bool { return Compare(a, b) == 0 }

// EqualName returns true if the domain names a and b are equal. See [CompareName].
func EqualName(a, b string) bool { return CompareName(a, b) == 0 }
