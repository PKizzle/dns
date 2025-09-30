package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"codeberg.org/miekg/dns/cmd/atomdns/atom"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers"
)

//go:generate go run man_generate.go

const Version = "009"

func main() {
	var (
		flagHandler bool
		flagVersion bool
		flagConf    string
	)
	flag.BoolVar(&flagHandler, "handler", false, "show sorted list of handlers")
	flag.BoolVar(&flagVersion, "version", false, "show version")
	flag.BoolVar(&flagVersion, "v", false, "show version")
	flag.StringVar(&flagConf, "conf", "Conffile", "config to load")
	flag.StringVar(&flagConf, "c", "Conffile", "config to load")

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

	confdata, err := os.ReadFile(flagConf)
	if err != nil {
		slog.Error("Failed to parse configuration", slog.String("path", flagConf), slog.Any("error", err))
		os.Exit(1)
	}
	s, err := atom.New(flagConf, bytes.NewReader(confdata))
	if err != nil {
		slog.Error("Failed to create server", slog.Any("error", err))
		slog.Error(err.Error())
		os.Exit(1)
	}

	if err := s.Start(); err != nil {
		slog.Error("Failed to start server", slog.Any("error", err))
		os.Exit(1)
	}

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)
	if !s.Quiet {
		fmt.Println(banner())
	}
	sig := <-sigchan
	s.Shutdown(context.TODO())
	slog.Info("Received signal, stopping", "signal", sig)
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
