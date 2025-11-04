//go:build windows
// +build windows

package reuse

import (
	"fmt"
	"net"
)

const (
	supportsReusePort = false
	supportsReuseAddr = false
)

func ListenTCP(network, addr string, reuseport, reuseaddr bool) (net.Listener, error) {
	if reuseport || reuseaddr {
		// TODO(tmthrgd): return an error?
	}

	return net.Listen(network, addr)
}

func ListenUDP(network, addr string, reuseport, reuseaddr bool) (net.PacketConn, error) {
	if reuseport || reuseaddr {
		// TODO(tmthrgd): return an error?
	}

	return net.ListenPacket(network, addr)
}

// this is just for test compatibility
func checkReuseport(fd uintptr) (bool, error) {
	return false, fmt.Errorf("not supported")
}

// this is just for test compatibility
func checkReuseaddr(fd uintptr) (bool, error) {
	return false, fmt.Errorf("not supported")
}
