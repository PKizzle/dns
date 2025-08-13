// Package dnsutil contains function that are useful in the context of working with the DNS.
package dnsutil

// Trim removes the zone component from q. It returns the trimmed
// name or an error is zone is longer then qname. The trimmed name will be returned
// without a trailing dot.
func Trim(q string, z string) string {
	zl := Count(z)
	i, ok := Prev(q, zl)
	if ok || i-1 < 0 {
		return ""
	}
	// This includes the '.', remove on return
	return q[:i-1]
}

/*
// IsBelow?
// IsSubDomain checks if child is indeed a child of the parent. If child and parent
// are the same domain true is returned as well.
func IsSubDomain(parent, child string) bool {
	// Entire child is contained in parent
	return CompareDomainName(parent, child) == CountLabel(parent)
}
*/
