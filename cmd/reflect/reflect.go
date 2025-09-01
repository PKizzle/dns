// Copyright 2011 Miek Gieben. All rights reserved.
//
// Reflect is a small name server which sends back the IP address of its client, the recursive resolver.
// When queried for type A (resp. AAAA), it sends back the IPv4 (resp. v6) address.
// In the additional section the port number and transport are shown.
//
// Basic use pattern:
//
//	dig @localhost -p 8053 whoami.miek.nl A
//
//	;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2157
//	;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
//	;; QUESTION SECTION:
//	;whoami.miek.nl.			IN	A
//
//	;; ANSWER SECTION:
//	whoami.miek.nl.		0	IN	A	127.0.0.1
//
//	;; ADDITIONAL SECTION:
//	whoami.miek.nl.		0	IN	TXT	"Port: 56195 (udp)"
//
// Similar services: whoami.ultradns.net, whoami.akamai.net. Also (but it
// is not their normal goal): rs.dns-oarc.net, porttest.dns-oarc.net,
// amiopen.openresolvers.org.
//
// Original version is from: Stephane Bortzmeyer <stephane+grong@bortzmeyer.org>.
//
// Adapted to Go (i.e. completely rewritten) by Miek Gieben <miek@miek.nl>.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime/pprof"
	"runtime/trace"
	"strconv"
	"syscall"

	"codeberg.org/miekg/dns"
)

var (
	flagcpu   = flag.Bool("cpu", false, "write cpu profile to cpu.out")
	flagtrace = flag.Bool("trace", false, "write trace profile to trace.out")
)

const dom = "whoami.miek.nl."

func reflect(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	var (
		v4  bool
		rr  dns.RR
		str string
		a   net.IP
	)
	if err := r.Unpack(); err != nil {
		log.Fatalf("%s", err.Error())
	}
	// Reuse r, do remember to call Pack yourself.
	r.Response, r.Answer, r.Ns, r.Extra, r.Pseudo = true, nil, nil, nil, nil

	if ip, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		str = "Port: " + strconv.Itoa(ip.Port) + " (udp)"
		a = ip.IP
		v4 = a.To4() != nil
	}
	if ip, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		str = "Port: " + strconv.Itoa(ip.Port) + " (tcp)"
		a = ip.IP
		v4 = a.To4() != nil
	}

	if v4 {
		rr = &dns.A{Hdr: dns.Header{Name: dom, Class: dns.ClassINET}, A: a.To4()}
	} else {
		rr = &dns.AAAA{Hdr: dns.Header{Name: dom, Class: dns.ClassINET}, AAAA: a}
	}

	t := &dns.TXT{Hdr: dns.Header{Name: dom, Class: dns.ClassINET}, Txt: []string{str}}

	switch r.Question[0].(type) {
	case *dns.TXT:
		r.Answer = []dns.RR{t}
		r.Extra = []dns.RR{rr}
	case *dns.AAAA, *dns.A:
		r.Answer = []dns.RR{rr}
		r.Extra = []dns.RR{t}
	}

	r.Pack()
	io.Copy(w, r)
}

func serve(net string) {
	server := &dns.Server{Addr: "[::]:8053", Net: net, ReusePort: true, MaxTCPQueries: -1}
	if err := server.ListenAndServe(); err != nil {
		log.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
	}
}

func main() {
	flag.Parse()

	if *flagtrace {
		f, err := os.Create("trace.out")
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		trace.Start(f)
		defer trace.Stop()
	}

	if *flagcpu {
		f, err := os.Create("cpu.out")
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	dns.HandleFunc("miek.nl.", reflect)
	for range 10 {
		go serve("tcp")
		go serve("udp")
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)
}
