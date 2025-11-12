package dnsutil

import (
	"strings"
)

// Join joins labels to form a fully qualified domain name. If the last label is
// the root label it is ignored. Not other syntax checks are performed.
func Join(ls ...string) string {
	ll := len(ls)
	if ls[ll-1] == "." {
		return strings.Join(ls[:ll-1], ".") + "."
	}
	return Fqdn(strings.Join(ls, "."))
}
