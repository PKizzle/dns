// Package dnstest allows for easy testing of DNS client against a test server.
package dnstest

import (
	"net"
	"time"

	"codeberg.org/miekg/dns"
)

// Recorder is a type of ResponseWriter that captures the all the messages written to it.
// If Discard is true, this effectively a dns.DiscardWriter.
type Recorder struct {
	conn    net.Conn
	Discard bool // When true the message is recorded, but not written to the underlaying connection.
	Msgs    []*dns.Msg
	Start   time.Time
}

var _ dns.ResponseWriter = &Recorder{}

// NewRecorder makes and returns a new Recorder, with start time set to now.
func NewRecorder(w dns.ResponseWriter) *Recorder {
	if w == nil {
		return &Recorder{Start: time.Now()}
	}
	return &Recorder{conn: w.Conn(), Start: time.Now()}
}

func (r *Recorder) Conn() net.Conn        { return r }
func (r *Recorder) Hijack()               {}
func (r *Recorder) Session() *dns.Session { return nil }

// Write is a wrapper that records the message that gets written to it.
func (r *Recorder) Write(b []byte) (int, error) {
	// See [Msg.WriteTo] that defaults to TCP
	msg := &dns.Msg{Data: b[2:]}
	err := msg.Unpack()
	if err != nil {
		return 0, err
	}
	r.Msgs = append(r.Msgs, msg)

	if r.Discard {
		return len(b), nil
	}
	if r.conn != nil {
		return r.conn.Write(b)
	}
	return len(b), nil
}

func (r *Recorder) Read(b []byte) (n int, err error)   { return len(b), nil }
func (r *Recorder) Close() error                       { return nil }
func (r *Recorder) LocalAddr() net.Addr                { return nil }
func (r *Recorder) RemoteAddr() net.Addr               { return nil }
func (r *Recorder) SetDeadline(t time.Time) error      { return nil }
func (r *Recorder) SetReadDeadline(t time.Time) error  { return nil }
func (r *Recorder) SetWriteDeadline(t time.Time) error { return nil }
