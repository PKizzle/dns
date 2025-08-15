// Package dnstest allows for easy testing of DNS client against a test server.
package dnstest

import (
	"time"

	"codeberg.org/miekg/dns"
)

// Recorder is a type of ResponseWriter that captures the Msg's data written to it.
type Recorder struct {
	dns.ResponseWriter
	Msg   *dns.Msg
	Start time.Time
}

// NewRecorder makes and returns a new Recorder, with start time set to now.
func NewRecorder(w dns.ResponseWriter) *Recorder {
	return &Recorder{ResponseWriter: w, Start: time.Now()}
}

// Write is a wrapper that records the length of the message that gets written.
// Write overrides the wrapped ResponseWriter's write method.
func (r *Recorder) Write(p []byte) (int, error) {
	n, err := r.ResponseWriter.Write(p)
	if err == nil {
		r.Msg = &dns.Msg{Data: p}
		r.Msg.Unpack()
	}
	return n, err
}
