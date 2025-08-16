// Package dnsutil contains function that are useful in the context of working with the DNS.
package dnsutil

// Trim removes the zone component from q. It returns the trimmed
// name or an error is zone is longer than q. The trimmed name will be returned without a trailing dot.
func Trim(q string, z string) string {
	zl := Count(z)
	i, ok := Prev(q, zl)
	if ok || i-1 < 0 {
		return ""
	}
	// This includes the '.', remove on return
	return q[:i-1]
}

// IsBelow checks if child sits below parent in the DNS tree. If child and parent
// are at the same level, true is returned as well.
func IsBelow(parent, child string) bool { return CommonSuffix(parent, child) == Count(parent) }
