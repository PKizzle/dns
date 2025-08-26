//go:build ignore

package dns

import (
	"context"
	"io"
	"net"
	"time"
)

// A Transfer defines parameters that are used during a zone transfer.
type Transfer struct {
	*Transport // If Transport is nil it gets a copy of DefaultTransport.
}

// In performs an incoming transfer with the server on address via network. If m.Data is empty, In calls m.Pack().
// Network should always be "tcp".
func (t *Transfer) In(ctx context.Context, m *Msg, network, address string) (env chan *Envelope, err error) {
	if t.Transport == nil {
		t.Transport = NewDefaultTransport()
	}

	conn, err := t.Transport.dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return t.InWithConn(ctx, m, conn)
}

// InWithConn is like [In], but takes a [net.Conn], also see [Client.ExchangeWithConn].
func (t *Transfer) InWithConn(ctx context.Context, m *Msg, conn net.Conn) (env chan *Envelope, err error) {
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

	conn, err := c.Transport.dial(ctx, network, address)
	if err != nil {
		return nil, 0, err
	}

	env = make(chan *Envelope)
	switch {
	case axfr:
		go t.inAXFR(ctx, m, env, conn)
	case ixfr:
		//		go t.inIXFR(ctx, m, env, conn)
	}

	return env, nil
}

func (t *Transfer) inAXFR(ctx context.Context, m *Msg, env chan *Envelope, conn net.Conn) {
	defer func() {
		// First close the connection, then the channel. This allows functions blocked on the channel to
		// assume that the connection is closed and no further operations are pending when they resume.
		conn.Close()
		close(env)
	}()

	options := &TSIGOption{}

	if t.MsgSecretFunc != nil && t.TSIGSigner != nil {
		err := TSIGSign(m, t.MsgSecretFunc, t.TSIGSigner, options)
		if err != nil && err != ErrNoTSIG {
			env <- &Envelope{Error: err}
			return
		}
	}

	remote := &response{conn: conn} // for Session() call in msg.go#L926
	if _, err := io.Copy(remote, m); err != nil {
		env <- &Envelope{Error: err}
		return
	}

	if err := ctx.Err(); err != nil {
		env <- &Envelope{Error: err}
		return
	}

	r := new(Msg)
	r.Data = m.Data
	r.Options = OptionUnpackHeader
	first := true
	for {
		conn.SetReadDeadline(time.Now().Add(t.ReadTimeout))
		if _, err := io.Copy(r, conn); err != nil {
			env <- &Envelope{Error: err}
			return
		}

		if err := ctx.Err(); err != nil {
			env <- &Envelope{Error: err}
			return
		}

		if err := r.Unpack(); err != nil {
			env <- &Envelope{r.Answer, err}
			return
		}

		if m.ID != r.ID {
			env <- &Envelope{r.Answer, ErrID}
			return
		}

		if r.Rcode != RcodeSuccess {
			env <- &Envelope{r.Answer, ErrRcode}
			return
		}
		r.Options = OptionUnpack
		if err := r.Unpack(); err != nil {
			env <- &Envelope{Error: err}
		}

		if t.MsgSecretFunc != nil && t.TSIGVerifier != nil {
			err := TSIGVerify(m, t.MsgSecretFunc, t.TSIGVerifier, options)
			if err != nil { // ErrNoTSIG is an actual problem here, as we expect one.
				env <- &Envelope{Error: err}
				return
			}
		}

		if first {
			if !isSOAFirst(r) {
				env <- &Envelope{r.Answer, ErrSOA}
				return
			}
			first = !first
			options.TimersOnly = true
			if len(r.Answer) == 1 { // only one answer that is SOA, receive more
				env <- &Envelope{r.Answer, nil}
				continue
			}
		}

		if isSOALast(r) { // ends the transfer
			env <- &Envelope{RR: r.Answer}
			return
		}
		env <- &Envelope{RR: r.Answer}
		options.TimersOnly = true
	}
}

/*
func (t *Transfer) inIxfr(q *Msg, c chan *Envelope) {
	var serial uint32 // The first serial seen is the current server serial
	axfr := true
	n := 0
	qser := q.Ns[0].(*SOA).Serial
	defer func() {
		// First close the connection, then the channel. This allows functions blocked on
		// the channel to assume that the connection is closed and no further operations are
		// pending when they resume.
		t.Close()
		close(c)
	}()
	timeout := dnsTimeout
	if t.ReadTimeout != 0 {
		timeout = t.ReadTimeout
	}
	for {
		t.SetReadDeadline(time.Now().Add(timeout))
		in, err := t.ReadMsg()
		if err != nil {
			c <- &Envelope{nil, err}
			return
		}
		if q.Id != in.Id {
			c <- &Envelope{in.Answer, ErrId}
			return
		}
		if in.Rcode != RcodeSuccess {
			c <- &Envelope{in.Answer, &Error{err: fmt.Sprintf(errXFR, in.Rcode)}}
			return
		}
		if n == 0 {
			// Check if the returned answer is ok
			if !isSOAFirst(in) {
				c <- &Envelope{in.Answer, ErrSOA}
				return
			}
			// This serial is important
			serial = in.Answer[0].(*SOA).Serial
			// Check if there are no changes in zone
			if qser >= serial {
				c <- &Envelope{in.Answer, nil}
				return
			}
		}
		// Now we need to check each message for SOA records, to see what we need to do
		t.tsigTimersOnly = true
		for _, rr := range in.Answer {
			if v, ok := rr.(*SOA); ok {
				if v.Serial == serial {
					n++
					// quit if it's a full axfr or the the servers' SOA is repeated the third time
					if axfr && n == 2 || n == 3 {
						c <- &Envelope{in.Answer, nil}
						return
					}
				} else if axfr {
					// it's an ixfr
					axfr = false
				}
			}
		}
		c <- &Envelope{in.Answer, nil}
	}
}
*/

// Out performs an outgoing transfer with the client connecting in w. Basic use pattern:
//
//	env := make(chan *dns.Envelope)
//	tr := new(dns.Transfer)
//	var wg sync.WaitGroup
//	w.Hijack() // hijack the connection as we can close the connection when done
//	wg.Add(1)
//	go func() {
//		tr.Out(w, r, ch)
//		wg.Done()
//	}()
//	env <- &dns.Envelope{RR: []dns.RR{SOA, rr1, rr2, rr3, SOA}}
//	close(env)
//	wg.Wait() // wait until everything is written out
//	w.Close() // close connection
//
// The server is responsible for sending the correct sequence of RRs through the channel ch.
func (t *Transfer) Out(w ResponseWriter, q *Msg, ch chan *Envelope) error {
	timersonly := false

	for env := range ch {
		r := new(Msg)
		dnsutilSetReply(r, q)

		r.Authoritative = true
		r.Answer = env.RR

		if err := r.Pack(); err != nil {
			return err
		}

		// TSIG TODO
		if _, err := io.Copy(w, r); err != nil {
			return err
		}
		timersonly = true
	}
	timersonly = timersonly
	return nil
}
