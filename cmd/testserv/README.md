testserv is a DNS server/router, written in Go, that chains handlers. Each handler performs a (DNS) function.
It architecture is identical to HTTP servers with middleware.

testserv is a fast and flexible DNS server. The key word here is _flexible_: with testserv you
are able to do what you want with your DNS data by utilizing handlers. If some functionality is not
provided out of the box you can add it by writing a handler.

Currently testserv is able to:

- Serve zone data from a file; with DNSSEC support (_file_), plus:
  - Zone tranfers.
  - DNSSEC signing.
- Load balancing of responses (_loadbalance_).
- Serve as a router to router queries to some other (recursive) nameserver (_route_).
- Provide query logging (_log_).
- Provide DNS64 IPv6 Translation (_dns64_).
- Provide metrics (by using Prometheus) (_prometheus_).
- Profiling support (_pprof_).
- ... and more.

## Compilation from Source

To compile testserv, we assume you have a working Go setup. See various tutorials if you don’t have
that already configured.

First, make sure your golang version is 1.21 or higher as `go mod` support and other api is needed.
See [here](https://github.com/golang/go/wiki/Modules) for `go mod` details.
Then, check out the project and run `make` to compile the binary:

```
$ git clone https://codeberg.org/miekg/dns
$ cd dns/cmd/testserv
$ go build
```

This should yield a `testserv` binary.

## Examples

The configuration of testserv is done through a file named `Conffile`. When testserv starts, it will
look for the `Conffile` from the current working directory. A `Conffile` for testserv server that listens
on port `53` and enables `whoami` plugin is:

```conffile
. {
    whoami
}
```
