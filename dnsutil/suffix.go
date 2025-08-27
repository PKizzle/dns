package dnsutil

// CommonSuffix compares the names a and b and returns how many labels they have in common starting
// from the *right*. The comparison stops at the first inequality. The names are downcased
// before the comparison. For example:
//
// www.miek.nl. and miek.nl. have two labels in common: miek and nl
// www.miek.nl. and www.bla.nl. have one label in common: nl
//
// a and b must be syntactically valid domain names.
func CommonSuffix(a, b string) (n int) {
	// the first check: root label
	if a == "." || b == "." {
		return 0
	}

	a1 := Split(a)
	b1 := Split(b)

	j1 := len(a1) - 1 // end
	i1 := len(a1) - 2 // start
	j2 := len(b1) - 1
	i2 := len(b1) - 2
	// the second check can be done here: last/only label
	// before we fall through into the for-loop below
	if compareLabel(a[a1[j1]:], b[b1[j2]:]) == 0 {
		n++
	} else {
		return
	}
	for {
		if i1 < 0 || i2 < 0 {
			break
		}
		if compareLabel(a[a1[i1]:a1[j1]], b[b1[i2]:b1[j2]]) == 0 {
			n++
		} else {
			break
		}
		j1--
		i1--
		j2--
		i2--
	}
	return
}
