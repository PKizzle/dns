//go:build windows

package dns

import (
	"log"
	"net"

	"golang.org/x/net/ipv4"
)

func (srv *Server) listenUDP(pc net.PacketConn) {
	if f := srv.NotifyStartedFunc; f != nil {
		f(srv.ctx)
	}
	xpc := ipv4.NewPacketConn(pc) // suspect this somehow works on Linux, but not other OSes.
	// Buffer to hold the incoming packet data
	buf := make([]byte, 1024)
	for {
		select {
		case <-srv.shutdown:
			pc.Close()
			srv.once.Do(func() { close(srv.exited) })
			return
		default:
		}
		n, _, src, err := xpc.ReadFrom(buf)
		if err != nil {
			log.Printf("error : %s", err)
			continue
		}
		if n < MsgHeaderSize {
			log.Println("short read")
			continue
		}
		r := &Msg{Data: buf[:n]}
		w := &response{conn: pc.(*net.UDPConn), session: &Session{src.(*net.UDPAddr), nil}}
		go func() {
			srv.serveDNS(w, r)
		}()
	}
}
