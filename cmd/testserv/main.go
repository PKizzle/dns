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
	"codeberg.org/miekg/dns/cmd/testserv/handlers/global"
	"codeberg.org/miekg/dns/cmd/testserv/handlers/metrics"
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

func serve(server *dns.Server, net string, global *global.Global) {
	// TODO: make this into proper dnsserver function.
	server.Net = net
	i := uint64(0)
	N := global.MetricsN
	server.MsgInvalidFunc = func(_ *dns.Msg, _ error) {
		if i%N == 0 {
			metrics.Dropped.Inc()
		}
		i++
	}
	if err := global.Startup(); err != nil {
		slog.Error("Failed to run startup for " + net + "server: " + err.Error())
		os.Exit(1)
	}

	if err := server.ListenAndServe(); err != nil {
		slog.Error("Failed to setup the " + net + " server: " + err.Error())
		os.Exit(1)
	}
	if err := global.Shutdown(); err != nil {
		slog.Warn("Failed to run shutdown for " + net + " server: " + err.Error())
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

	global, err := parse(mux, *flagConf)
	if err != nil {
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
		go serve(srv, "tcp", global)
		go serve(srv, "udp", global)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)
}
