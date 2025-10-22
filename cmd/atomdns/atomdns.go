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

const Version = "022"

func main() {
	var (
		flagHandler bool
		flagVersion bool
		flagCheck   bool
		flagConf    string
		confdata    []byte
		err         error
	)
	flag.BoolVar(&flagHandler, "H", false, "show sorted list of handlers")
	flag.BoolVar(&flagVersion, "V", false, "show version")
	flag.BoolVar(&flagCheck, "C", false, "check the configuration")
	flag.StringVar(&flagConf, "config", "", "config to load")
	flag.StringVar(&flagConf, "c", "", "config to load")

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

	if flagConf == "" {
		confdata = []byte(builtin)
		flagConf = "<builtin>"
	} else {
		confdata, err = os.ReadFile(flagConf)
		if err != nil {
			slog.Error("Failed to parse configuration", slog.String("path", flagConf), slog.Any("error", err))
			os.Exit(1)
		}
	}

	s, err := atom.New(flagConf, bytes.NewReader(confdata))
	if err != nil {
		slog.Error("Failed to create server", slog.Any("error", err))
		os.Exit(1)
	}
	if flagCheck {
		os.Exit(0)
	}

	if err := s.Start(); err != nil {
		slog.Error("Failed to start server", slog.Any("error", err))
		os.Exit(1)
	}

	go func() {
		// dies with process
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, syscall.SIGHUP)
		for {
			select {
			case sig := <-sigchan:
				slog.Info("Received signal, reloading", "signal", sig)
				if err := s.Reload(); err != nil {
					slog.Error("Failed to reload server", slog.Any("error", err))
				}
				signal.Notify(sigchan, syscall.SIGHUP)
				if !s.Quiet {
					fmt.Println(banner())
				}
			}
		}
	}()

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

const builtin = `
{
	dns {
		addr [::]:1053
	}
}

example.org {
	log
	whoami
}
`
