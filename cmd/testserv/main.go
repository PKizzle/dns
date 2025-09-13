package main

import (
	"context"
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
	"codeberg.org/miekg/dns/cmd/testserv/handlers/global"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/metrics"
)

//go:generate go run man_generate.go

const Version = "001"

func serve(server *dns.Server, net string, global *global.Global) {
	// TODO: make this into proper dnsserver function.
	server.Net = net
	i := uint64(0)
	N := global.MetricsN
	server.MsgInvalidFunc = func(_ *dns.Msg, _ error) {
		if N == 0 {
			return
		}
		if i%N == 0 {
			metrics.Dropped.Inc()
		}
		i++
	}
	if err := global.Startup(); err != nil {
		slog.Error("Failed to run startup: " + err.Error())
		os.Exit(1)
	}

	if err := server.ListenAndServe(); err != nil {
		slog.Error("Failed to start: " + err.Error())
		os.Exit(1)
	}
}

func main() {
	var (
		flagProfile bool
		flagHandler bool
		flagVersion bool
		flagConf    string
		flagPort    string
	)
	flag.BoolVar(&flagProfile, "cpuprofile", false, "write cpu profile to cpu.out")
	flag.StringVar(&flagConf, "conf", "Conffile", "config to load")
	flag.StringVar(&flagConf, "c", "Conffile", "config to load")
	flag.BoolVar(&flagHandler, "handler", false, "list installed handlers")
	flag.BoolVar(&flagHandler, "h", false, "list installed handlers")
	flag.BoolVar(&flagVersion, "version", false, "show version")
	flag.BoolVar(&flagVersion, "v", false, "show version")
	flag.StringVar(&flagPort, "port", "53", "default port")
	flag.StringVar(&flagPort, "p", "53", "default port")

	flag.Parse()
	if flagVersion {
		fmt.Println(Version)
		return
	}
	if flagProfile {
		f, err := os.Create("cpu.out")
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	if flagHandler {
		for h := range handlers.StringToHandler {
			fmt.Println(h)
		}
		return
	}

	mux := dns.NewServeMux()

	global, err := parse(mux, flagConf)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	srv := &dns.Server{
		Handler:       mux,
		Addr:          "[::]:" + flagPort,
		ReuseAddr:     true,
		ReusePort:     true,
		MaxTCPQueries: -1,
	}

	for range runtime.NumCPU() * 3 {
		go serve(srv, "tcp", global)
		go serve(srv, "udp", global)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	if err := global.Shutdown(); err != nil {
		slog.Warn("Failed to run shutdown: " + err.Error())
	}
	srv.Shutdown(context.TODO())
	fmt.Printf("Signal (%s) received, stopping\n", s)
}
