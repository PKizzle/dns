package dnsutil

type skip int

// These constant determine the direction of the Skip function.
const (
	SkipForward skip = iota + 1
	SkipBackword
)

// Skip skips n labels in direction, the returns bool
func Skip(s string, n int, direction skip) (string, bool) {

}
