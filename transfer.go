package dns

import (
	"context"
)

// Envelope is used when doing a zone transfer with a remote server.
type Envelope struct {
	Msg   *Msg  // The message as returned by the remote server, or the one to be send to the remote.
	Error error // If something went wrong, this contains the error.
}

// TransferIn performs a zone transfer with address over network, the message m is used to ask for the transfer and
// should have an [AXFR] or [IXFR] RR in the question section.  The caller is responsible for setting up and verifying TSIG and or
// SIG(0) on the message send, and the messages returned on the channel.
func (c *Client) TransferIn(ctx context.Context, m *Msg, network, address string) (<-chan *Envelope, error) {
	return nil, nil
}

// Out performs an outgoing transfer with the client connecting in w. The server is responsible for sending
// the correct messages through the channel. The server also needs to take care of setting up and verifying TSIG and or
// SIG(0) on the messages sent through the channel.
//
// Example setup:
//
//	env := make(chan<- *dns.Envelope)
//	w.Hijack() // hijack the connection as we should close when done
//	c := new(dns.Client)
//	var wg sync.WaitGroup
//	wg.Go(func() { c.TransferOut(w, r, env) })
//	for i := range msgs {
//		env <- &dns.Envelope{Msg: msgs[i]}
//	}
//	close(env)
//	wg.Wait() // wait until everything is written out
//	w.Close() // close connection
//
// The server is responsible for sending the correct sequence of RRs through the channel ch.
func (c *Client) TransferOut(w ResponseWriter, r *Msg, env chan<- *Envelope) error {
	return nil
}
