package dns

import (
	"context"
	"io"
	"net"
	"time"
)

// Envelope is used when doing a zone transfer with a remote server.
type Envelope struct {
	*Msg        // The message as returned by the remote server, or the one to be send to the remote.
	Error error // If something went wrong, this contains the error.
}

// TransferIn performs a zone transfer with address over network, the message m is used to ask for the transfer and
// should have an [AXFR] or [IXFR] RR in the question section.  The caller is responsible for setting up and verifying TSIG and or
// SIG(0) on the message send, and the messages returned on the channel. The messages returned are "lightly" unpacked, just like in
// [dns.HandleFunc].
// If m's buffer is empty Transfer will call m.Pack(). If the client's transport is nil NewDefaultTransport will be used.
func (c *Client) TransferIn(ctx context.Context, m *Msg, network, address string) (<-chan *Envelope, error) {
	if c.Transport == nil {
		c.Transport = NewDefaultTransport()
	}
	conn, err := c.Transport.dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return c.TransferInWithConn(ctx, m, conn)
}

// TransferInWithConnn behaves like [client.TransferIn], but with a supplied connection.
func (c *Client) TransferInWithConn(ctx context.Context, m *Msg, conn net.Conn) (<-chan *Envelope, error) {
	_, axfr := m.Question[0].(*AXFR)
	_, ixfr := m.Question[0].(*IXFR)
	if !axfr && !ixfr {
		return nil, &Error{"unsupported transfer type"}
	}

	if len(m.Data) == 0 {
		if err := m.Pack(); err != nil {
			return nil, err
		}
	}

	ch := make(chan *Envelope)
	switch {
	case axfr:
		go c.axfrTransferIn(ctx, m, ch, conn)
	case ixfr:
		//		go t.inIXFR(ctx, m, ch, conn)
	}

	return ch, nil
}

func (c *Client) axfrTransferIn(ctx context.Context, m *Msg, ch chan<- *Envelope, conn net.Conn) {
	defer func() {
		// First close the connection, then the channel. This allows functions blocked on the channel to
		// assume that the connection is closed and no further operations are pending when they resume.
		conn.Close()
		close(ch)
	}()

	remote := &response{conn: conn} // for Session() call in msg.go#L926
	if _, err := io.Copy(remote, m); err != nil {
		ch <- &Envelope{Error: err}
		return
	}

	if err := ctx.Err(); err != nil {
		ch <- &Envelope{Error: err}
		return
	}

	r := &Msg{Data: m.Data}
	r.Options = OptionUnpackHeader
	dnsutilSetReply(r, m)
	for {
		// first message must hace axfre in answe
		conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
		if _, err := io.Copy(r, conn); err != nil {
			if isEOFOrClosedNetwork(err) {
				break
			}
			ch <- &Envelope{Error: err}
			return
		}

		if err := ctx.Err(); err != nil {
			ch <- &Envelope{Error: err}
			return
		}

		if err := r.Unpack(); err != nil {
			ch <- &Envelope{r, err}
			return
		}

		if m.ID != r.ID {
			ch <- &Envelope{r, ErrID}
			return
		}

		if r.Rcode != RcodeSuccess {
			ch <- &Envelope{r, ErrRcode}
			return
		}
		r.Options = OptionUnpack
		ch <- &Envelope{Msg: r}
	}
}

// Out performs an outgoing transfer with the client connecting in w. The server is responsible for sending
// the correct messages through the channel. And also needs to take care of setting up and verifying TSIG and or
// SIG(0) on the messages sent through the channel. If the Data buffers of the message sent on the channel are
// zero, TransferOut call Pack().
//
// Example setup:
//
//	env := make(chan<- *dns.Envelope)
//	c := new(dns.Client)
//	w.Hijack() // hijack the connection as we should close when done
//	var wg sync.WaitGroup
//	wg.Go(func() { c.TransferOut(w, env) })
//	for i := range msgs {
//		env <- &dns.Envelope{Msg: msgs[i]}
//	}
//	close(env)
//	wg.Wait() // wait until everything is written out
//	w.Close() // close connection
//
// The server is responsible for sending the correct sequence of Msgs through the channel ch.
func (c *Client) TransferOut(w ResponseWriter, ch <-chan *Envelope) error {
	for env := range ch {
		if len(env.Msg.Data) == 0 {
			if err := env.Msg.Pack(); err != nil {
				return err
			}
		}

		if _, err := io.Copy(w, env.Msg); err != nil {
			return err
		}
	}
	return nil
}
