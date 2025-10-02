package global

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/conffile"
)

func (g *Global) SetupTLS(d conffile.Dispenser) error {
	for d.NextBlock(0) {
		switch d.Val() {
		case "cert":
			args := d.RemainingArgs() // we don't have co.RemainingPaths there
			if len(args) < 2 || len(args) > 3 {
				return d.ArgErr()
			}
			paths := make([]string, len(args))
			for i, arg := range paths {
				if filepath.IsAbs(arg) {
					paths[i] = arg
					continue
				}
				paths[i] = filepath.Join(g.Root, arg)
			}
			var roots *x509.CertPool
			cert, err := tls.LoadX509KeyPair(args[0], args[1])
			if err != nil {
				return fmt.Errorf("could not load TLS certificate pair: %s", err)
			}
			if len(args) == 3 {
				if roots, err = loadCA(args[2]); err != nil {
					return fmt.Errorf("could not load CA: %s", err)
				}
			}
			g.TlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      roots,
				NextProtos:   []string{"h2", "http/1.1"},
			}
		case "contact":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			g.TlsContact = args[0]
		case "path":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			if !filepath.IsAbs(args[0]) {
				args[0] = filepath.Join(g.Root, args[0])
			}
			g.TlsPath = args[0]
		default:
			return d.ArgErr()
		}
	}
	return nil
}

func loadCA(path string) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ok := roots.AppendCertsFromPEM(pem)
	if !ok {
		return nil, fmt.Errorf("could not read root certificates: %s", err)
	}
	return roots, nil
}
