package dnstest

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
)

func Server(pc net.PacketConn, l net.Listener, opts ...func(*dns.Server)) (*dns.Server, string, chan error, error) {
	srv := &dns.Server{PacketConn: pc, Listener: l, ReadTimeout: time.Hour}

	srv.Init()
	waitLock := sync.Mutex{}
	waitLock.Lock()
	srv.NotifyStartedFunc = waitLock.Unlock
	srv.MsgInvalidFunc = func(m *dns.Msg, err error) { fmt.Printf("invalid message: %s - %T\n", err, err) }

	for _, opt := range opts {
		opt(srv)
	}

	var (
		addr   string
		closer io.Closer
	)
	if l != nil {
		addr = l.Addr().String()
		closer = l
	} else {
		addr = pc.LocalAddr().String()
		closer = pc
	}

	// fin must be buffered so the goroutine below won't block forever if fin is never read from. This always happens
	// if the channel is discarded.
	fin := make(chan error, 1)

	go func() {
		fin <- srv.ActivateAndServe()
		closer.Close()
	}()

	waitLock.Lock()
	return srv, addr, fin, nil
}

func UDPServer(laddr string, opts ...func(*dns.Server)) (*dns.Server, string, chan error, error) {
	pc, err := net.ListenPacket("udp", laddr)
	if err != nil {
		return nil, "", nil, err
	}
	return Server(pc, nil, opts...)
}

func TCPServer(laddr string, opts ...func(*dns.Server)) (*dns.Server, string, chan error, error) {
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, "", nil, err
	}
	return Server(nil, l, opts...)
}

/*
func RunLocalTLSServer(laddr string, config *tls.Config) (*dns.Server, string, chan error, error) {
	return RunLocalTCPServer(laddr, func(srv *dns.Server) {
		srv.Listener = tls.NewListener(srv.Listener, config)
	})
}


func RunLocalUnixGramServer(laddr string, opts ...func(*dns.Server)) (*dns.Server, string, chan error, error) {
	pc, err := net.ListenPacket("unixgram", laddr)
	if err != nil {
		return nil, "", nil, err
	}

	return RunLocalServer(pc, nil, opts...)
}

func RunLocalUnixSeqPacketServer(laddr string) (chan interface{}, string, error) {
	pc, err := net.Listen("unixpacket", laddr)
	if err != nil {
		return nil, "", err
	}

	shutdownChan := make(chan interface{})
	go func() {
		pc.Accept()
		<-shutdownChan
	}()

	return shutdownChan, pc.Addr().String(), nil
}
*/
