package dns

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// Transport is the transport used in [Client], it deals with all the networking.
type Transport struct {
	// 	Do the RoundTripper interface?

	// DialContext specifies the dial function for creating unencrypted TCP or UDP connections.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// TLSClientConfig specifies the TLS configuration to use with tls.Client.
	// If nil, the default configuration is used.
	TLSClientConfig *tls.Config

	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// If non zero TSIG signing and verification is done on messages that qualify when doing zone transfers.
	TSIGSigner
	TSIGVerifier
}

// DefaultTransport is the default transport in client, when none is set.
var DefaultTransport = &Transport{
	DialContext: defaultTransportDialContext(&net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 3 * time.Second,
	}),
	ReadTimeout:  2 * time.Second,
	WriteTimeout: 2 * time.Second,
}

func defaultTransportDialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return dialer.DialContext
}
