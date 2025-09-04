package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"

	"codeberg.org/miekg/dns"
)

var cpuprofile = flag.Bool("cpuprofile", false, "write cpu profile to cpu.out")

const dom = "whoami.miek.nl."

func serve(server *dns.Server, net string) {
	server.Net = net
	if err := server.ListenAndServe(); err != nil {
		log.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
	}
}

func main() {
	flag.Parse()
	if *cpuprofile {
		f, err := os.Create("cpu.out")
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	mux := dns.NewServeMux()

	if err := parse(mux); err != nil {
		log.Fatal(err)
	}

	srv := &dns.Server{
		Handler:       mux,
		Addr:          "[::]:8054",
		ReusePort:     true,
		MaxTCPQueries: -1,
	}

	for range 10 {
		go serve(srv, "tcp")
		go serve(srv, "udp")
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)
}
