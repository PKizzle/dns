package dns

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
)

// Default maximum number of TCP queries before we close the socket.
const maxTCPQueries = 128

// ListenAndServe Starts a server on address and network specified Invoke handler
// for incoming queries.
func ListenAndServe(addr string, network string, handler Handler) error {
	server := &Server{Addr: addr, Net: network, Handler: handler}
	return server.ListenAndServe()
}

// ListenAndServeTLS acts like [http.ListenAndServeTLS].
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

// ActivateAndServe activates a server with a listener from systemd, l and p should not both be non-nil.
// If both l and p are not nil only p will be used. Invoke handler for incoming queries.
func ActivateAndServe(l net.Listener, p net.PacketConn, handler Handler) error {
	server := &Server{Listener: l, PacketConn: p, Handler: handler}
	return server.ActivateAndServe()
}

// InvalidMsgFunc is a listener hook for observing incoming messages that were discarded
// because they could not be parsed or an eariler error in the server.
// Every message that is read by a Reader will eventually be provided to the Handler, or passed to this function.
type InvalidMsgFunc func(m *Msg, err error)

// DefaultMsgInvalidFunc is the default function used in case no InvalidMsgFunc is set. It is defined to be a
// noop.
func DefaultMsgInvalidFunc(m *Msg, err error) {}

// A Server defines parameters for running an DNS server.
type Server struct {
	// Address to listen on, ":dns" if empty.
	Addr string
	// If "tcp" or "tcp-tls" (DNS over TLS) it will invoke a TCP listener, otherwise an UDP one.
	Net string
	// TCP Listener to use, this is to aid in systemd's socket activation.
	Listener net.Listener
	// TLS connection configuration
	TLSConfig *tls.Config
	// UDP "Listener" to use, this is to aid in systemd's socket activation.
	PacketConn net.PacketConn
	// Handler to invoke, dns.DefaultServeMux if nil.
	Handler Handler
	// Default buffer size to use to read incoming UDP messages. If not set it defaults to MinMsgSize (512 B).
	UDPSize int
	// The read timeout vaule for new connections, defaults to 2 * time.Second.
	ReadTimeout time.Duration
	// TCP idle timeout for multiple queries, if nil, defaults to 8 * time.Second (RFC 5966).
	IdleTimeout func() time.Duration
	// If NotifyStartedFunc is set it is called once the server has started listening.
	NotifyStartedFunc func()
	// MsgInvalidFunc is optional, it will be called if a message is received but cannot be parsed.
	MsgInvalidFunc InvalidMsgFunc
	// Maximum number of TCP queries before we close the socket. Default is maxTCPQueries (128), unlimited if -1.
	MaxTCPQueries int
	// Whether to set the SO_REUSEPORT socket option, allowing multiple listeners to be bound to a single address.
	// It is only supported on certain GOOSes and when using ListenAndServe.
	ReusePort bool
	// Whether to set the SO_REUSEADDR socket option, allowing multiple listeners to be bound to a single address.
	// Crucially this allows binding when an existing server is listening on `0.0.0.0` or `::`.
	// It is only supported on certain GOOSes and when using ListenAndServe.
	ReuseAddr bool

	ctx      context.Context // server wide context to signal shutdown to running handlers
	cancel   context.CancelFunc
	exited   chan struct{}
	shutdown chan bool
}

// Init sets some default values in Server.
func (srv *Server) Init() {
	if srv.UDPSize == 0 {
		srv.UDPSize = MinMsgSize
	}
	if srv.MsgInvalidFunc == nil {
		srv.MsgInvalidFunc = DefaultMsgInvalidFunc
	}
	if srv.Handler == nil {
		srv.Handler = DefaultServeMux
	}
	srv.ctx, srv.cancel = context.WithCancel(context.Background())
	srv.exited = make(chan struct{})
	srv.shutdown = make(chan bool)
}

// ListenAndServe starts a nameserver on the configured address in *Server.
func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":domain"
	}

	srv.Init()

	switch srv.Net {
	case "tcp", "tcp4", "tcp6":
		l, err := listenTCP(srv.Net, addr, srv.ReusePort, srv.ReuseAddr)
		if err != nil {
			return err
		}
		srv.Listener = l
		srv.listenTCP(l)
		return nil
	case "tcp-tls", "tcp4-tls", "tcp6-tls":
		if srv.TLSConfig == nil || (len(srv.TLSConfig.Certificates) == 0 && srv.TLSConfig.GetCertificate == nil) {
			return errors.New("dns: neither Certificates nor GetCertificate set")
		}
		network := strings.TrimSuffix(srv.Net, "-tls")
		l, err := listenTCP(network, addr, srv.ReusePort, srv.ReuseAddr)
		if err != nil {
			return err
		}
		l = tls.NewListener(l, srv.TLSConfig)
		srv.listenTCP(l)
		return nil
	case "udp", "udp4", "udp6":
		l, err := listenUDP(srv.Net, addr, srv.ReusePort, srv.ReuseAddr)
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

// ActivateAndServe starts a nameserver with the PacketConn or Listener configured in *Server. Its main use is to start a server from systemd.
func (srv *Server) ActivateAndServe() error {
	if srv.PacketConn != nil {
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
	srv.cancel()
	if srv.Listener != nil {
		srv.Listener.Close()
	}
	if srv.PacketConn != nil {
		srv.PacketConn.Close()
	}
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
	timeout := srv.getReadTimeout()

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
				continue
			}
			conn.SetReadDeadline(time.Now().Add(timeout))
			go srv.serveTCP(&wg, conn)
		}
	}
}

// batchSize controls the maximum of packets we should read using recvmmsg, using ReadBatch, a tradeoff
// needs to be made with how much memory needs to be pre-allocated and how fast things should go. It is
// set to set to 15.
// If this is a not a const, but var, or worse a field in [Server] it's about 10k qps *slower*.
const batchSize = 15 // cd cmd/reflect; go test -v -count=1 # check the perf values, 15 does 360K on my M2 8-core with Asahi Linux

// listenUDP starts a UDP listener for the server.
func (srv *Server) listenUDP(pc net.PacketConn) {
	if srv.NotifyStartedFunc != nil {
		srv.NotifyStartedFunc()
	}
	timeout := srv.getReadTimeout()

	var wg sync.WaitGroup
	// suspect this somehow works on Linux, but not other OSes.
	xpc := ipv4.NewPacketConn(pc)

	for {
		select {
		case <-srv.shutdown:
			pc.Close()
			wg.Wait()
			close(srv.exited)
			return
		default:
			bufs := make([][]byte, batchSize, batchSize)
			msgs := make([]ipv4.Message, batchSize, batchSize)
			for i := range batchSize {
				bufs[i] = make([]byte, srv.UDPSize)
				msgs[i].Buffers = [][]byte{bufs[i]}
				msgs[i].OOB = make([]byte, oobSize)
			}
			xpc.SetReadDeadline(time.Now().Add(timeout))
			n, err := xpc.ReadBatch(msgs, 0)
			if err != nil {
				continue
			}
			for i := range n {
				msg := msgs[i]
				raddr := msg.Addr
				oob := msg.OOB[:msg.NN]

				r := &Msg{Data: msg.Buffers[0][:msg.N]}
				w := &response{conn: pc.(*net.UDPConn), session: &Session{raddr.(*net.UDPAddr), oob}, hijacked: new(atomic.Bool)}

				go srv.serveUDP(&wg, w, r)
			}
		}
	}
}

func (srv *Server) serveUDP(wg *sync.WaitGroup, w *response, r *Msg) {
	wg.Add(1)
	srv.serveDNS(wg, w, r)
}

// Serve a new TCP connection.
func (srv *Server) serveTCP(wg *sync.WaitGroup, conn net.Conn) {
	w := &response{conn: conn, hijacked: new(atomic.Bool)}

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
			if errors.Is(err, io.EOF) {
				break
			}
			continue
		}

		if !w.hijacked.Load() {
			wg.Add(1)
		}
		go func() {
			srv.serveDNS(wg, w, r)
		}()

		if w.hijacked.Load() {
			wg.Done() // call done because hijack has been called in the handler
			break     // client will call Close() themselves
		}
		// The first read uses the read timeout, the rest use the idle timeout.
		timeout = idleTimeout
	}

	if !w.hijacked.Load() {
		wg.Wait() // wait for anyone still processing
		w.Close()
	}
}

func (srv *Server) serveDNS(wg *sync.WaitGroup, w *response, r *Msg) {
	r.Options = OptionUnpackQuestion | OptionUnpackHeader

	err := r.Unpack()
	if err != nil {
		srv.MsgInvalidFunc(r, err)
		wg.Done()
		return
	}
	if r.Response == true {
		srv.MsgInvalidFunc(r, &Error{err: "r.Response is set"})
	}
	r.Options = 0
	srv.Handler.ServeDNS(srv.ctx, w, r)
	wg.Done()
}
