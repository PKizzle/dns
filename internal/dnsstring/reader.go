package dnsstring

import (
	"io"
	"strings"
)

// Reader wraps a string and guarantees the stream ends with a '\n'.
// If the string already ends with a newline, it behaves identically to
// strings.NewReader. Otherwise it appends exactly one '\n' at EOF.
type Reader struct {
	r      *strings.Reader
	needed bool
	sent   bool
}

// NewReader returns a Reader for s.
func NewReader(s string) *Reader {
	return &Reader{
		r:      strings.NewReader(s),
		needed: len(s) == 0 || s[len(s)-1] != '\n',
	}
}

// Read implements io.Reader.
func (r *Reader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)

	// If the underlying reader is exhausted and we still owe a newline,
	// append it into whatever space is left in p.
	if err == io.EOF && r.needed && !r.sent {
		if n < len(p) {
			r.sent = true
			p[n] = '\n'
			n++
			return n, io.EOF
		}
		// p was fully consumed by the underlying read; the newline will
		// be delivered on the next call (err stays io.EOF, but we return
		// n > 0 so the caller loops back).
		return n, nil
	}

	return n, err
}
