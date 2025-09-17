atomdns is a DNS server/router, written in Go, that chains handlers. Each handler performs a (DNS) function.
It architecture is identical to HTTP servers with middleware. The order if the handlers in the configuration
determines the order in which they are executed. (If you know CoreDNS; you might know that has a fixed order -
atomdns is _different_).

atomdns is a fast and flexible DNS server. The key word here is _flexible_: with atomdns you
are able to do what you want with your DNS data by utilizing handlers. If some functionality is not
provided out of the box you can add it by writing a handler.

Currently atomdns is able to:

- Serve zone data from a file; with DNSSEC support (_dbfile_), plus:
  - Zone tranfers and notifies.
  - DNSSEC signing.
- Provide query logging (_log_).
- Access control for queryes (_acl_).
- Provide metrics (by using Prometheus) (_metrics_).
- ... and more.
- Load balancing of responses (_loadbalance_). [TODO]
- Serve as a router to router queries to some other (recursive) nameserver (_route_). [TODO]

## Compilation from Source

To compile atomdns, we assume you have a working Go setup. See various tutorials if you don’t have
that already configured.

First, make sure your golang version is 1.21 or higher as `go mod` support and other api is needed.
See [here](https://github.com/golang/go/wiki/Modules) for `go mod` details.
Then, check out the project and run `make` to compile the binary:

```
$ git clone https://codeberg.org/miekg/dns
$ cd dns/cmd/atomdns
$ go build
```

This should yield a `atomdns` binary.

## Examples

The configuration of atomdns is done through a file named `Conffile`. When atomdns starts, it will
look for the `Conffile` from the current working directory. A `Conffile` for atomdns server that listens
on port `53` and enables `whoami` handler is:

```conffile
. {
    whoami
}
```
