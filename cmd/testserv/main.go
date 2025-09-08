package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"syscall"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/testserv/handlers"
)

//go:generate go run man_generate.go

const Version = "001"

var (
	flagProfile = flag.Bool("cpuprofile", false, "write cpu profile to cpu.out")
	flagConf    = flag.String("conf", "Conffile", "config to load")
	flagPlug    = flag.Bool("handlers", false, "list installed handlers")
	flagVersion = flag.Bool("version", false, "show version")
	flagQuiet   = flag.Bool("quiet", false, "quiet mode (no initialization output)")
	flagPort    = flag.String("port", "53", "default port")
)

func serve(server *dns.Server, net string) {
	server.Net = net
	if err := server.ListenAndServe(); err != nil {
		slog.Error("Failed to setup the " + net + " server: " + err.Error())
		os.Exit(1)
	}
}

func main() {
	flag.Parse()
	if *flagVersion {
		fmt.Println(Version)
		return
	}
	if *flagProfile {
		f, err := os.Create("cpu.out")
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	if *flagPlug {
		for h := range handlers.StringToHandler {
			fmt.Println(h)
		}
		return
	}

	mux := dns.NewServeMux()

	if err := parse(mux, *flagConf); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	srv := &dns.Server{
		Handler:       mux,
		Addr:          "[::]:" + *flagPort,
		ReusePort:     true,
		MaxTCPQueries: -1,
	}

	for range runtime.NumCPU() * 3 {
		go serve(srv, "tcp")
		go serve(srv, "udp")
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)
}
