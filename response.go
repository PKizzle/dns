package dns

import (
	"io"
	"net"
)

type response struct {
	*Network      // see [msg.Network] used for UDP reply routing
	closed   bool // connection has been closed
	hijacked bool // connection has been hijacked by handler, TODO, flesh this out
	Writer   net.Conn
}

// Write writes the buffer p to the m.Data.
func (w *response) Write(p []byte) (n int, err error) { return w.Writer.Write(p) }

// Read read the data from m.Data into p.
func (w *response) Read(p []byte) (n int, err error) { return w.Read(p) }

// LocalAddr implements the ResponseWriter.LocalAddr method.
func (w *response) LocalAddr() net.Addr {
	switch sock := w.Writer.(type) {
	case *net.UDPConn:
		return sock.LocalAddr()
	case *net.TCPConn:
		return sock.LocalAddr()
	default:
		panic("dns: internal error: no sock in response")
	}
}

// RemoteAddr implements the ResponseWriter.RemoteAddr method.
func (w *response) RemoteAddr() net.Addr {
	switch sock := w.Writer.(type) {
	case *net.UDPConn:
		// session stuff, also in here??
		return sock.RemoteAddr()
	case *net.TCPConn:
		return sock.RemoteAddr()
	default:
		panic("dns: internal error: no sock in response")
	}
}

// Hijack implements the ResponseWriter.Hijack method.
func (w *response) Hijack() { w.hijacked = true }

// Close implements the ResponseWriter.Close method
func (w *response) Close() error {
	if w.closed {
		return &Error{err: "connection already closed"}
	}
	if sock, ok := w.Writer.(io.Closer); ok {
		w.closed = true
		return sock.Close()
	}
	return nil
}
