package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"codeberg.org/miekg/dns/cmd/atomdns/atom"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers"
)

//go:generate go run man_generate.go

const Version = "005"

func main() {
	var (
		flagHandler bool
		flagVersion bool
		flagQuiet   bool
		flagConf    string
		flagPort    string
	)
	flag.BoolVar(&flagHandler, "handler", false, "show sorted list of handlers")
	flag.BoolVar(&flagVersion, "version", false, "show version")
	flag.BoolVar(&flagVersion, "v", false, "show version")

	flag.StringVar(&flagPort, "port", "53", "default port")
	flag.StringVar(&flagPort, "p", "53", "default port")
	flag.StringVar(&flagConf, "conf", "Conffile", "config to load")
	flag.StringVar(&flagConf, "c", "Conffile", "config to load")
	flag.BoolVar(&flagQuiet, "quiet", false, "mute startup notifications")
	flag.BoolVar(&flagQuiet, "q", false, "mute startup notifications")

	flag.Parse()
	if flagVersion {
		fmt.Println(Version)
		return
	}
	if flagHandler {
		hs := []string{}
		for h := range handlers.StringToHandler {
			hs = append(hs, h)
		}
		sort.Strings(hs)
		fmt.Println(strings.Join(hs, "\n"))
		return
	}

	options := atom.ServerOption{
		Quiet:   flagQuiet,
		Addr:    net.JoinHostPort("::", flagPort),
		Servers: runtime.NumCPU() * 3,
	}

	confdata, err := os.ReadFile(flagConf)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	s, err := atom.New(flagConf, bytes.NewReader(confdata), options)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	if err := s.Start(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)
	if !flagQuiet {
		fmt.Println(banner())
	}
	sig := <-sigchan
	s.Shutdown(context.TODO())
	slog.Info(fmt.Sprintf("Signal (%s) received, stopping", sig))
}

func banner() string {
	const banner = `
  ┏━┓  ╺┳╸  ┏━┓  ┏┳┓
  ┣━┫   ┃   ┃ ┃  ┃┃┃ DNS              v%s
  ╹ ╹   ╹   ┗━┛  ╹ ╹
  High performance and flexible DNS server
  https://atomdns.miek.nl
__________________________________\o/_______`
	return fmt.Sprintf(banner[1:], Version) // [1:] remove first \n, while keeping the formatting in the const
}
