//go:build windows

package dns

import (
	"net"
	"sync"

	"golang.org/x/net/ipv4"
)

// listenUDP starts a UDP listener for the server.
func (srv *Server) listenUDP(pc net.PacketConn) {
	if f := srv.NotifyStartedFunc; f != nil {
		f(srv.ctx)
	}

	var wg sync.WaitGroup
	xpc := ipv4.NewPacketConn(pc)

Read:
	for {
		select {
		case <-srv.shutdown:
			pc.Close()
			wg.Wait()
			srv.once.Do(func() { close(srv.exited) })
			return
		default:
			buf := srv.MsgPool.Get()
			n, _, src, err := xpc.ReadFrom(buf)
			if err != nil {
				continue Read
			}
			r := &Msg{Data: buf[:n]}
			w := &response{conn: pc.(*net.UDPConn), session: &Session{src.(*net.UDPAddr), nil}}
			wg.Add(1) // no wg.Go to prevent defer usage
			go func() {
				srv.serveDNS(w, r)
				wg.Done()
			}()
		}
	}
}
