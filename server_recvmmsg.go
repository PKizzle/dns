//go:build unix

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
	xpc := ipv4.NewPacketConn(pc) // suspect this somehow works on Linux, but not other OSes.

Read:
	for {
		select {
		case <-srv.shutdown:
			pc.Close()
			wg.Wait()
			srv.once.Do(func() { close(srv.exited) })
			return
		default:
			bufs := make([][]byte, BatchSize, BatchSize)
			msgs := make([]ipv4.Message, BatchSize, BatchSize)
			for i := range BatchSize {
				bufs[i] = srv.MsgPool.Get()
				msgs[i].Buffers = [][]byte{bufs[i]}
				msgs[i].OOB = make([]byte, oobSize)
			}

			// if we set the read deadline is will timeout every ReadTimeout and reallocate the msgs, we are
			// also a server, so just wait for incoming messages.

			n, err := xpc.ReadBatch(msgs, 0)
			if err != nil {
				// there is no Msg to speak of so we can't call MsgInvalidFunc...
				for i := range BatchSize {
					srv.MsgPool.Put(bufs[i])
				}
				continue Read
			}
			for _, msg := range msgs[:n] {
				r := &Msg{Data: msg.Buffers[0][:msg.N]}
				w := &response{conn: pc.(*net.UDPConn), session: &Session{msg.Addr.(*net.UDPAddr), msg.OOB[:msg.NN]}}
				wg.Add(1) // no wg.Go to prevent defer usage
				go func() {
					srv.serveDNS(w, r)
					wg.Done()
				}()
			}
			// return if we over-allocated
			for j := n + 1; j < BatchSize; j++ {
				srv.MsgPool.Put(bufs[j])
			}
		}
	}
}
