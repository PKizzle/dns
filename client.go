package dns

// A DNS client implementation, modelled after http.Client

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"time"
)

// A Client is a DNS client. It is safe to use a client from multiple goroutines.
type Client struct {
	// 	Transport RoundTripper Do the RoundTripper interface?
	*Transport
}

type Transport struct {
	// DialContext specifies the dial function for creating unencrypted TCP or UDP connections.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// TLSClientConfig specifies the TLS configuration to use with tls.Client.
	// If nil, the default configuration is used.
	TLSClientConfig *tls.Config
}

var DefaultTransport = &Transport{
	DialContext: defaultTransportDialContext(&net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 3 * time.Second,
	}),
}

func defaultTransportDialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return dialer.DialContext
}

// Exchange performs a synchronous UDP query. It sends the message m to the address
// contained in a and waits for a reply. Exchange does not retry a failed query, nor
// will it fall back to TCP in case of truncation.
//
// See [client.Exchange] for more information on setting larger buffer sizes.
func Exchange(ctx context.Context, m *Msg, network, address string) (r *Msg, err error) {
	client := Client{Transport: DefaultTransport}
	r, _, err = client.Exchange(ctx, m, network, address)
	return r, err
}

// Exchange performs a synchronous query. It sends the message m to the address
// contained in a and waits for a reply. Basic use pattern with a *dns.Client:
//
//	c := new(dns.Client)
//	resp, rtt, err := c.Exchange(m, "127.0.0.1:53")
//
// If client does not have a transport [DefaultTransport] is used.
// Exchange does not retry a failed query, nor will it fall back to TCP in case of truncation.
//
// It is up to the caller to create a message that allows for larger responses to be returned. Specifically
// this means setting [Msg.Bufsize] that will advertise a larger buffer. Messages without an Bufsize will
// fall back to the historic limit of 512 octets (bytes).
//
// The full binary data is included in the (decoded) message r.Data.
//
// Exchange calls Pack() on m if len(m.Data) == 0.
func (c *Client) Exchange(ctx context.Context, m *Msg, network, address string) (r *Msg, rtt time.Duration, err error) {
	var conn net.Conn
	if c.Transport == nil {
		conn, err = DefaultTransport.DialContext(ctx, network, address)
	} else {
		conn, err = c.Transport.DialContext(ctx, network, address)
	}
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	return c.ExchangeWithConn(ctx, m, conn)
}

// ExchangeWithConn behaves like [client.Exchange], but with a supplied connection.
func (c *Client) ExchangeWithConn(ctx context.Context, m *Msg, conn net.Conn) (r *Msg, rtt time.Duration, err error) {
	t := time.Now()
	remote := &response{conn: conn} // for Session() call in msg.go#L926

	if len(m.Data) == 0 {
		return nil, time.Since(t), ErrMsgUnpacked
	}

	if _, err := io.Copy(remote, m); err != nil {
		return nil, time.Since(t), err
	}

	r = new(Msg)
	r.Data = m.Data
	if len(r.Data) < int(m.UDPSize) {
		r.Data = append(r.Data, make([]byte, (int(m.UDPSize)-len(r.Data)))...)
	}
	if len(r.Data) < MinMsgSize {
		r.Data = append(r.Data, make([]byte, MinMsgSize-len(r.Data))...)
	}

	if _, err := io.Copy(r, conn); err != nil {
		return nil, time.Since(t), err
	}

	err = r.Unpack()
	if err != nil {
		return r, time.Since(t), err
	}
	if r.ID != m.ID {
		return r, time.Since(t), ErrID
	}

	return r, time.Since(t), nil
}
