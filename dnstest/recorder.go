// Package dnstest allows for easy testing of DNS clients against a test server.
package dnstest

import (
	"net"
	"time"

	"codeberg.org/miekg/dns"
)

// Recorder is a type of ResponseWriter that captures the all the messages written to it.
// If Discard is true, this effectively an [io.Discard] writer.
type Recorder struct {
	w       dns.ResponseWriter
	Discard bool       // When true the message is recorded, but not written to the underlaying connection.
	Msgs    []*dns.Msg // All messages written to it.
	Msg     *dns.Msg   // Msg contains the last message written.
	Start   time.Time  // Time when the recorder was created.
}

var _ dns.ResponseWriter = &Recorder{}

// NewRecorder makes and returns a new Recorder, with start time set to now.
func NewRecorder(w dns.ResponseWriter) *Recorder {
	if w == nil {
		return &Recorder{Start: time.Now()}
	}
	return &Recorder{w: w, Start: time.Now()}
}

func (r *Recorder) Write(b []byte) (int, error) {
	// See [Msg.WriteTo] that defaults to TCP.
	msg := &dns.Msg{Data: b[2:]}
	err := msg.Unpack()
	if err != nil {
		return 0, err
	}
	r.Msg = msg
	r.Msgs = append(r.Msgs, msg)

	if r.Discard {
		return len(b), nil
	}
	if r.w != nil {
		return r.w.Write(b)
	}
	return len(b), nil
}

// Implement the net.Conn interface.
func (r *Recorder) Read(b []byte) (int, error)       { return len(b), nil }
func (r *Recorder) SetDeadline(time.Time) error      { return nil }
func (r *Recorder) SetReadDeadline(time.Time) error  { return nil }
func (r *Recorder) SetWriteDeadline(time.Time) error { return nil }

func (r *Recorder) Conn() net.Conn {
	return r // we are a net.Conn ourselves
}

func (r *Recorder) Hijack() {
	if r.w != nil {
		r.w.Hijack()
	}
}

func (r *Recorder) Session() *dns.Session {
	if r.w != nil {
		return r.w.Session()
	}
	return nil
}

func (r *Recorder) Close() error {
	if r.w != nil {
		return r.w.Close()
	}
	return nil
}

func (r *Recorder) LocalAddr() net.Addr {
	if r.w != nil {
		return r.w.LocalAddr()
	}
	return nil
}

func (r *Recorder) RemoteAddr() net.Addr {
	if r.w != nil {
		return r.w.RemoteAddr()
	}
	return nil
}
