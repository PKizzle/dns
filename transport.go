package dns

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// Transport is the transport used in [Client], it deals with all the networking.
type Transport struct {
	// Dialer is used used to set local address and timeouts.
	Dialer *net.Dialer

	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// TLSClientConfig specifies the TLS configuration to use with DialTLS, if TLSConfig is not nil it will
	// be used to dial.
	TLSConfig *tls.Config

	// If non zero TSIG signing and verification is done on messages that qualify when doing zone transfers.
	TSIGSigner
	TSIGVerifier
}

// DefaultTransport is the default transport in client, when none is set. Note changing this value how global
// effects to future [Client]s and [Transfer]s.
var DefaultTransport = Transport{
	Dialer: &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 3 * time.Second,
	},
	ReadTimeout:  2 * time.Second,
	WriteTimeout: 2 * time.Second,
}

// NewDefaultTransport returns a copy of [DefaultTransport].
func NewDefaultTransport() *Transport {
	d := DefaultTransport
	return &d
}

// dial dials address via network. If tls config is set, a tls dialer is used.
func (t *Transport) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if t.TLSConfig != nil {
		dialer := tls.Dialer{NetDialer: t.Dialer, Config: t.TLSConfig}
		return dialer.DialContext(ctx, network, address)
	}
	return t.Dialer.DialContext(ctx, network, address)
}
