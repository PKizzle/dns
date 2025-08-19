package dns

import (
	"crypto/tls"
	"net"
	"time"
)

// Transport is the transport used in [Client], it deals with all the networking.
type Transport struct {
	// Dialer is used used to set local address and timeouts.
	Dialer *net.Dialer

	// TLSClientConfig specifies the TLS configuration to use with DialTLS, if TLSConfig is not nil it will
	// be used to dial.
	TLSConfig *tls.Config

	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// If non zero TSIG signing and verification is done on messages that qualify when doing zone transfers.
	TSIGSigner
	TSIGVerifier
}

// DefaultTransport is the default transport in client, when none is set.
var DefaultTransport = &Transport{
	Dialer: &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 3 * time.Second,
	},
	ReadTimeout:  2 * time.Second,
	WriteTimeout: 2 * time.Second,
}
