package dns

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

// Default maximum number of TCP queries before we close the socket.
const maxTCPQueries = 128

// ListenAndServe Starts a server on address and network specified Invoke handler
// for incoming queries.
func ListenAndServe(addr string, network string, handler Handler) error {
	server := &Server{Addr: addr, Net: network, Handler: handler}
	return server.ListenAndServe()
}

// ListenAndServeTLS acts like http.ListenAndServeTLS, more information in
// http://golang.org/pkg/net/http/#ListenAndServeTLS
func ListenAndServeTLS(addr, certFile, keyFile string, handler Handler) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	config := tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	server := &Server{
		Addr:      addr,
		Net:       "tcp-tls",
		TLSConfig: &config,
		Handler:   handler,
	}

	return server.ListenAndServe()
}

// ActivateAndServe activates a server with a listener from systemd,
// l and p should not both be non-nil.
// If both l and p are not nil only p will be used.
// Invoke handler for incoming queries.
func ActivateAndServe(l net.Listener, p net.PacketConn, handler Handler) error {
	server := &Server{Listener: l, PacketConn: p, Handler: handler}
	return server.ActivateAndServe()
}

// A Server defines parameters for running an DNS server.
type Server struct {
	// Address to listen on, ":dns" if empty.
	Addr string
	// if "tcp" or "tcp-tls" (DNS over TLS) it will invoke a TCP listener, otherwise an UDP one
	Net string
	// TCP Listener to use, this is to aid in systemd's socket activation.
	Listener net.Listener
	// TLS connection configuration
	TLSConfig *tls.Config
	// UDP "Listener" to use, this is to aid in systemd's socket activation.
	PacketConn net.PacketConn
	// Handler to invoke, dns.DefaultServeMux if nil.
	Handler Handler
	// Default buffer size to use to read incoming UDP messages. If not set
	// it defaults to MinMsgSize (512 B).
	UDPSize int
	// The net.Conn.SetReadTimeout value for new connections, defaults to 2 * time.Second.
	ReadTimeout time.Duration
	// The net.Conn.SetWriteTimeout value for new connections, defaults to 2 * time.Second.
	WriteTimeout time.Duration
	// TCP idle timeout for multiple queries, if nil, defaults to 8 * time.Second (RFC 5966).
	IdleTimeout func() time.Duration
	// If NotifyStartedFunc is set it is called once the server has started listening.
	NotifyStartedFunc func()
	// Maximum number of TCP queries before we close the socket. Default is maxTCPQueries (128), unlimited if -1.
	MaxTCPQueries int
	// Whether to set the SO_REUSEPORT socket option, allowing multiple listeners to be bound to a single address.
	// It is only supported on certain GOOSes and when using ListenAndServe.
	ReusePort bool

	exited   chan struct{}
	shutdown chan bool
}

func (srv *Server) init() {
	if srv.UDPSize == 0 {
		srv.UDPSize = MinMsgSize
	}
	if srv.Handler == nil {
		srv.Handler = DefaultServeMux
	}
}

// ListenAndServe starts a nameserver on the configured address in *Server.
func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":domain"
	}

	srv.init()

	switch srv.Net {
	case "tcp", "tcp4", "tcp6":
		l, err := listenTCP(srv.Net, addr, srv.ReusePort)
		if err != nil {
			return err
		}
		srv.Listener = l
		srv.listenTCP(l)
		return nil
	case "tcp-tls", "tcp4-tls", "tcp6-tls":
		if srv.TLSConfig == nil || (len(srv.TLSConfig.Certificates) == 0 && srv.TLSConfig.GetCertificate == nil) {
			return errors.New("dns: neither Certificates nor GetCertificate set in Config")
		}
		network := strings.TrimSuffix(srv.Net, "-tls")
		l, err := listenTCP(network, addr, srv.ReusePort)
		if err != nil {
			return err
		}
		l = tls.NewListener(l, srv.TLSConfig)
		srv.listenTCP(l)
		return nil
	case "udp", "udp4", "udp6":
		l, err := listenUDP(srv.Net, addr, srv.ReusePort)
		if err != nil {
			return err
		}
		u := l.(*net.UDPConn)
		if e := setUDPSocketOptions(u); e != nil {
			u.Close()
			return e
		}
		srv.PacketConn = l
		srv.listenUDP(u)
		return nil
	}
	return &Error{err: "bad network"}
}

// ActivateAndServe starts a nameserver with the PacketConn or Listener
// configured in *Server. Its main use is to start a server from systemd.
func (srv *Server) ActivateAndServe() error {
	if srv.PacketConn != nil {
		// Check PacketConn interface's type is valid and value is not nil
		if t, ok := srv.PacketConn.(*net.UDPConn); ok && t != nil {
			if e := setUDPSocketOptions(t); e != nil {
				return e
			}
		}
		srv.listenUDP(srv.PacketConn)
	}
	if srv.Listener != nil {
		srv.listenTCP(srv.Listener)
	}
	return &Error{err: "bad listeners"}
}

// Shutdown shuts down a server. After a call to Shutdown, ListenAndServe and ActivateAndServe will return.
// A context.Context may be passed to limit how long to wait for connections to terminate. Not used at the moment.
func (srv *Server) Shutdown(ctx context.Context) {
	close(srv.shutdown)
	<-srv.exited
}

// getReadTimeout is a helper func to use system timeout if server did not intend to change it.
func (srv *Server) getReadTimeout() time.Duration {
	if srv.ReadTimeout != 0 {
		return srv.ReadTimeout
	}
	return 2 * time.Second
}

// listenTCP starts a TCP listener for the server.
func (srv *Server) listenTCP(ln net.Listener) {
	if srv.NotifyStartedFunc != nil {
		srv.NotifyStartedFunc()
	}

	var wg sync.WaitGroup

	for {
		select {
		case <-srv.shutdown:
			ln.Close()
			wg.Wait()
			close(srv.exited)
			return
		default:
			conn, err := ln.Accept()
			if err != nil {
				// skip (log, whatever)
				continue
			}
			go srv.serveTCP(&wg, conn)
		}
	}
}

// listenUDP starts a UDP listener for the server.
func (srv *Server) listenUDP(pc net.PacketConn) {
	if srv.NotifyStartedFunc != nil {
		srv.NotifyStartedFunc()
	}

	var wg sync.WaitGroup

	for {
		select {
		case <-srv.shutdown:
			pc.Close() // add more channels?
			wg.Wait()
			close(srv.exited)
			return
		default:
			r := &Msg{Data: make([]byte, srv.UDPSize)}

			oob := make([]byte, oobSize)
			n, oobn, _, raddr, err := pc.(*net.UDPConn).ReadMsgUDP(r.Data, oob)
			if err != nil {
				// nothing?? TODO
				continue
			}

			oob = oob[:oobn]
			w := &response{conn: pc.(*net.UDPConn), session: &Session{raddr, oob}}
			r.Data = r.Data[:n]
			go srv.serveUDP(&wg, w, r)
		}
	}
}

func (srv *Server) serveUDP(wg *sync.WaitGroup, w *response, r *Msg) {
	wg.Add(1)
	srv.serveDNS(wg, w, r)
}

// Serve a new TCP connection.
func (srv *Server) serveTCP(wg *sync.WaitGroup, conn net.Conn) {
	w := &response{conn: conn}

	idleTimeout := 2 * time.Second
	if srv.IdleTimeout != nil {
		idleTimeout = srv.IdleTimeout()
	}
	timeout := srv.getReadTimeout()

	limit := srv.MaxTCPQueries
	if limit == 0 {
		limit = maxTCPQueries
	}

	for q := 0; q < limit || limit == -1; q++ {
		conn.SetReadDeadline(time.Now().Add(timeout))

		r := &Msg{Data: make([]byte, srv.UDPSize)}
		if _, err := r.ReadFrom(conn); err != nil {
			// handle error, return turnong
			continue
		}

		wg.Add(1)
		srv.serveDNS(wg, w, r)

		if w.hijacked { // TODO
			break // client will call Close() themselves
		}
		// The first read uses the read timeout, the rest use the idle timeout.
		timeout = idleTimeout
	}

	if !w.hijacked {
		w.Close()
	}
}

func (srv *Server) serveDNS(wg *sync.WaitGroup, w *response, r *Msg) {
	defer wg.Done()

	r.Options = OptionUnpackQuestion | OptionUnpackHeader

	err := r.Unpack()
	if err != nil {
		// bogus, don't even reply
		return
	}
	// finally call the handler attached.
	srv.Handler.ServeDNS(w, r)
}

/*
// ConnectionState() implements the ConnectionStater.ConnectionState() interface.
func (w *response) ConnectionState() *tls.ConnectionState {
	type tlsConnectionStater interface {
		ConnectionState() tls.ConnectionState
	}
	if v, ok := w.tcp.(tlsConnectionStater); ok {
		t := v.ConnectionState()
		return &t
	}
	return nil
}
*/
