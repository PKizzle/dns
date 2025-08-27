package dns

import (
	"context"
	"io"
	"net"
	"time"
)

// Envelope is used when doing a zone transfer with a remote server.
type Envelope struct {
	RRs   []RR  // The RRs as returned by the remote server, or the ones to be send to the remote.
	Error error // If something went wrong, this contains the error.
}

// TransferIn performs a zone transfer with address over network, the message m is used to ask for the transfer and
// should have an [AXFR] or [IXFR] RR in the question section. If the pseudo section contains a (stub) TSIG or
// SIG0 record, TSIG or SIG0 signing is performed, see [TSIG.New] and [SIG.New].
// On the returned channel the received RRs are returned (and a non-nil erorr in case of an error). These RRs
// are as they were found, i.e. including the starting and ending SOA RRs.
//
// If m's buffer is empty Transfer will call m.Pack(). If the client's transport is nil DefaultTransport will be used.
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

	if c.TSIGSigner != nil && hasTSIG(m) != nil {
		if err := TSIGSign(m, c.TSIGSigner, &TSIGOption{}); err != nil {
			return nil, err
		}
	}
	// if.SIG0Signer != nil {}

	remote := &response{conn: conn} // for Session() call in msg.go#L926
	if _, err := io.Copy(remote, m); err != nil {
		return nil, err
	}

	ch := make(chan *Envelope)
	if axfr {
		go c.transferInAXFR(ctx, m, ch, conn)
	}
	if ixfr {
		// go c.transferInIXFR(ctx, m, ch, conn)
	}
	return ch, nil
}

func (c *Client) transferInAXFR(ctx context.Context, m *Msg, ch chan<- *Envelope, conn net.Conn) {
	defer func() {
		// First close the connection, then the channel. This allows functions blocked on the channel to
		// assume that the connection is closed and no further operations are pending when they resume.
		conn.Close()
		close(ch)
	}()

	options := TSIGOption{}
	if x := hasTSIG(m); x != nil {
		options.RequestMAC = x.MAC
	}
	r := &Msg{}
	r.Options = OptionUnpackHeader
	for {
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
			ch <- &Envelope{Error: err}
			return
		}

		if m.ID != r.ID {
			ch <- &Envelope{Error: ErrID.Fmt(": %d != %d", m.ID, r.ID)}
			return
		}

		if r.Rcode != RcodeSuccess {
			ch <- &Envelope{Error: ErrRcode}
			return
		}

		r.Options = OptionUnpack
		err := r.Unpack()
		if err != nil {
			ch <- &Envelope{RRs: r.Answer, Error: err}
		}

		// On first loop first be need to see a SOA RR.
		if !options.TimersOnly {
			if len(r.Answer) == 0 {
				ch <- &Envelope{Error: ErrSOA}
				return
			}
			if _, ok := r.Answer[0].(*SOA); !ok {
				ch <- &Envelope{Error: ErrSOA}
				return
			}
		}

		if c.TSIGVerifier != nil && hasTSIG(m) != nil {
			if err := TSIGVerify(m, c.TSIGVerifier, &options); err != nil {
				ch <- &Envelope{RRs: r.Answer, Error: err}
			}
		}
		ch <- &Envelope{RRs: r.Answer, Error: err}
		options.TimersOnly = true
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
func (c *Client) TransferOut(w ResponseWriter, r *Msg, env <-chan *Envelope) error {
	for e := range env {
		m := new(Msg)
		dnsutilSetReply(m, r)
		//		options
		m.Answer = e.RRs
		// tsig
		m.Pack()

		if _, err := io.Copy(w, m); err != nil {
			return err
		}
	}
	return nil
}

func hasTSIG(m *Msg) *TSIG {
	for i := range m.Pseudo {
		if t, ok := m.Pseudo[i].(*TSIG); ok {
			return t
		}
	}
	return nil
}
