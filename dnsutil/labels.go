package dnsutil

import (
	"strings"
)

// Join joins labels to form a fully qualified domain name. If the last label is
// the root label it is ignored. Not other syntax checks are performed.
func Join(labels ...string) string {
	ll := len(labels)
	if labels[ll-1] == "." {
		return strings.Join(labels[:ll-1], ".") + "."
	}
	return Fqdn(strings.Join(labels, "."))
}

// Prev returns the index of the label when starting from the right and jumping n labels to the left.
// The bool start is true when the start of the string has been overshot. Also see Next.
func Prev(s string, n int) (i int, start bool) {
	if s == "" {
		return 0, true
	}
	if n == 0 {
		return len(s), false
	}

	l := len(s) - 1
	if s[l] == '.' {
		l--
	}

	for ; l >= 0 && n > 0; l-- {
		if s[l] != '.' {
			continue
		}
		j := l - 1
		for j >= 0 && s[j] == '\\' {
			j--
		}

		if (j-l)%2 == 0 {
			continue
		}

		n--
		if n == 0 {
			return l + 1, false
		}
	}

	return 0, n > 1
}
