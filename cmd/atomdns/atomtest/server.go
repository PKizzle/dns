package atomtest

import (
	"context"
	"net"
	"strings"

	"codeberg.org/miekg/dns/cmd/atomdns/atom"
)

// New returns a server suitable for testing. Use cancel to shutdown the server
// Use [server.Addr] to get the listening addresses. NewTest starts 2 servers, one on UDP and another on TCP.
func New(config string) (*atom.Server, func(), error) {
	options := atom.ServerOption{Quiet: true, Addr: net.JoinHostPort("::", "0"), Servers: 1}
	s, err := atom.New("test", strings.NewReader(config), options)
	if err != nil {
		return nil, nil, err
	}
	if err := s.Start(); err != nil {
		return nil, nil, err
	}
	return s, func() { s.Shutdown(context.TODO()) }, nil
}
