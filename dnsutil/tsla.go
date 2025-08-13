package dnsutil

import (
	"fmt"
	"net"
	"strconv"
)

// TLSAName returns the ownername of a TLSA resource record as per the rules specified in RFC 6698, Section 3.
func TLSAName(name, service, network string) (string, error) {
	if !IsFqdn(name) {
		return "", fmt.Errorf("dnsutil: domain must be fully qualified")
	}
	p, err := net.LookupPort(network, service)
	if err != nil {
		return "", err
	}
	return "_" + strconv.Itoa(p) + "._" + network + "." + name, nil
}
