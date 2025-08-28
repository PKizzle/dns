package dns

import (
	"context"
	"io"
	"net"
	"time"
)

// Envelope is used when doing a zone transfer with a remote server.
type Envelope struct {
	Answer []RR  // The RRs as returned by the remote server, or the ones to be send to the remote.
	Error  error // If something went wrong, this contains the error.
}

// TransferIn performs a zone transfer with address over network, the message m is used to ask for the transfer and
// should have an [AXFR] or [IXFR] RR in the question section. If the pseudo section contains a (stub) TSIG or
// SIG0 record, TSIG or SIG0 signing is performed, see [TSIG.New] and [SIG.New] on how create such RRs. For
// this the client also need a [TSIGSigner] or [SIG0Signer].
// On the returned channel the received RRs are returned (and a non-nil erorr in case of an error). These RRs
// are as they were found, i.e. including the starting and ending SOA RRs.
//
// If m's buffer is empty TransferIn will call m.Pack(). If the clients's transport is nil [DefaultTransport] will
// be set and used.
//
// Setting up a transfer is done as follows:
//
//	c := dns.NewClient()
//	m := dns.NewMsg("example.org.", dns.TypeAXFR)
//	env, err := c.TransferIn(context.TODO(), m, "tcp", addr)
//	if err != nil {
//	   t.Fatal("failed to setup zone transfer in", err)
//	}
//
//	for e := range env {
//		if e.Error != nil {
//			// ...
//		}
//		// do things with e.Answer
//	}
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

	t := hasTSIG(m)
	options := TSIGOption{}
	r := &Msg{}
	for {
		r.Options = OptionUnpackHeader
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
			ch <- &Envelope{Error: ErrRcode.Fmt(": %s", sprintRcode(r.Rcode))}
			return
		}

		r.Options = OptionUnpack
		err := r.Unpack()
		if err != nil {
			ch <- &Envelope{Answer: r.Answer, Error: err}
		}

		// On first loop first be need to see a SOA RR.
		if !options.TimersOnly {
			if len(r.Answer) == 0 {
				ch <- &Envelope{Error: ErrSOA.Fmt(": empty answer")}
				return
			}
			if _, ok := r.Answer[0].(*SOA); !ok {
				ch <- &Envelope{Error: ErrSOA}
				return
			}
		}

		if c.TSIGSigner != nil && t != nil {
			if err := TSIGVerify(m, c.TSIGSigner, &options); err != nil {
				ch <- &Envelope{Answer: r.Answer, Error: err}
			}
		}
		ch <- &Envelope{Answer: r.Answer, Error: err}
		options.TimersOnly = true
		if hasTSIG(m) != nil {
			options.RequestMAC = hasTSIG(m).MAC
		}

		// If there is a SOA RR as the last we're done
		if len(r.Answer) > 0 {
			if _, ok := r.Answer[len(r.Answer)-1].(*SOA); ok {
				return
			}
		}
	}
}

// TransferOut performs an outgoing transfer with the client connecting in w.
//
// Example setup from within a dns.HandleFunc:
//
//		w.Hijack() // hijack the connection as we should close when done
//		env := make(chan *dns.Envelope)
//		c := dns.NewClient()
//		var wg sync.WaitGroup
//
//		wg.Go(func() {
//	        c.TransferOut(w, env)
//		    w.Close() // close connection
//	    })
//		env <- &dns.Envelope{Answer: []dns.RR{...}}
//		close(env)
//
// The server is responsible for sending the correct sequence of RRs through the channel env.
// If the clients's transport is nil [DefaultTransport] will be set and used.
func (c *Client) TransferOut(w ResponseWriter, r *Msg, env <-chan *Envelope) error {
	if c.Transport == nil {
		c.Transport = NewDefaultTransport()
	}

	t := hasTSIG(r)
	options := TSIGOption{}
	for e := range env {
		m := new(Msg)
		m.Authoritative = true
		dnsutilSetReply(m, r)
		m.Answer = e.Answer
		if t != nil {
			m.Pseudo = []RR{t} // need to change tsig rr, or not?
		}
		if err := m.Pack(); err != nil {
			return err
		}
		if c.TSIGSigner != nil && t != nil {
			if err := TSIGSign(m, c.TSIGSigner, &options); err != nil {
				return err
			}
		}

		if _, err := io.Copy(w, m); err != nil {
			return err
		}
		options.TimersOnly = true
		// request mac, denk het wel
	}
	return nil
}
