// Package dnsutil contains function that are useful in the context of working with the DNS.
package dnsutil

// Trim removes the zone component from s. It returns the trimmed
// name or an error is zone is longer than q. The trimmed name will be returned without a trailing dot.
func Trim(s string, z string) string {
	zl := Labels(z)
	i, ok := Prev(s, zl)
	if ok || i-1 < 0 {
		return ""
	}
	// This includes the '.', remove on return
	return s[:i-1]
}

// IsBelow checks if child sits below parent in the DNS tree, i.e. check if the child is a sub-domain of
// parent. If child and parent are at the same level, true is returned as well.
func IsBelow(parent, child string) bool { return Common(parent, child) == Labels(parent) }
