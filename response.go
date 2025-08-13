package dns

import (
	"io"
	"net"
)

// A ResponseWriter interface is used by an DNS handler to construct an DNS response.
type ResponseWriter interface {
	// LocalAddr returns the net.Addr of the server.
	LocalAddr() net.Addr
	// RemoteAddr returns the net.Addr of the client that sent the current request.
	RemoteAddr() net.Addr
	// Conn returns the underlaying connection.
	Conn() net.Conn
	// ResponseWriter must also implement the io.Writer interface.
	io.Writer
	// Session returns the UDP oob session data to correctly route UDP packets.
	Session() *Session
	// Hijack lets the caller take over the TCP connection. For UDP this has no effect.
	Hijack()
}

// response implements response.Writer
type response struct {
	session  *Session // used for UDP reply routing, needs to be in the interface! If needed
	hijacked bool     // connection has been hijacked by handler, TODO, flesh this out
	conn     net.Conn
}

func (w *response) Conn() net.Conn    { return w.conn }
func (w *response) Session() *Session { return w.session }

// Write writes the buffer p to the m.Data.
func (w *response) Write(p []byte) (n int, err error) { return w.conn.Write(p) }

// Read read the data from m.Data into p.
func (w *response) Read(p []byte) (n int, err error) { return w.conn.Read(p) }

// LocalAddr implements the ResponseWriter.LocalAddr method.
func (w *response) LocalAddr() net.Addr {
	switch sock := w.conn.(type) {
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
	if w.conn == nil {
		panic("dns: internal error, no writer in response")
	}
	switch sock := w.conn.(type) {
	case *net.UDPConn:
		return w.Session().RemoteAddr()
	case *net.TCPConn:
		return sock.RemoteAddr()
	default:
		panic("dns: internal error: no sock in response")
	}
}

// Hijack implements the ResponseWriter.Hijack method.
func (w *response) Hijack() { w.hijacked = true }

func (w *response) Close() error {
	if sock, ok := w.conn.(io.Closer); ok {
		return sock.Close()
	}
	return nil
}
