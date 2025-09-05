package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"syscall"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/testserv/handlers"
)

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
		log.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
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
			log.Fatal(err)
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
		log.Fatal(err)
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
