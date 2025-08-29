[![Go Report Card](https://goreportcard.com/badge/codeberg.org/miekg/dns)](https://goreportcard.com/report/codeberg.org/miekg/dns)
[![](https://godoc.org/coreberg.org/miekg/dns?status.svg)](https://godoc.org/codeberg.org/miekg/dns)

# Even more alternative approach to a DNS library (version 2)

# Status

- All basics work.
- Fast(er); recvmmsg and pipeling suppport.
- More convenience functions included in _dns_ or otherwise in _dnsutils_.
- Test helper function included _dnstest_.
- Example programs included _and_ benchmarked in `cmd/`.

See [open issues](https://codeberg.org/miekg/dns/issues) on the remaining work.

(Previous version is https://github.com/miekg/dns)

> Less is more.

Complete and usable DNS library. All Resource Records are supported, including the DNSSEC types. It follows a
lean and mean philosophy. Server side and client side programming is supported, i.e. you can build servers and
resolvers with it.

We try to keep the "main" branch as sane as possible and at the bleeding edge of standards, avoiding breaking
changes wherever reasonable. but because this version is young, we allow ourselves some more headroom.

The naming of types follows the RFCs. EDNS0 types are similarly named, for instance, DHU (Ds Hash Understood).
If there is a clash between an actual RR's and an EDNS0 one, the EDNS0 type will get an 'E' as prefix, e.g.
EDHU. This will also be done if the RR was named later than the EDNS0 option! The same is the for DSO (DNS
Stateful Operations), when clashing those types will be prefixed with a 'D'. If EDNS0 and DSO clash, EDNS0
wins.

# Goals

- KISS.
- Everything is an resource record.
- Small API.
- Fast.
  - The cmd/reflect server does 350K/280K UDP/TCP respectively.
- Improved naming by embracing sub-packages.

## Difference with github.com/miekg/dns

- Many functions (and new ones) are moved into dns/dnsutil.
- `RR` lost the `Type` and `Rdlength` fields, type is derived from the Go type, `Rdlength` served no function
  at all.
- `context.Context` is in the correct places.
- `ServeDNS` now has a context.Context, with `Zone(ctx)` you retrieve the pattern (usually) zone that lead to
  invocation of this Handler.
- `internal/*` packages that hold code that used to be private, but was cluttering; also allowed for better
  naming.

  - builtin perf testing with internal/dnsperf

- Interfaces do not have private methods.
- `Msg` contains a buffer named `Data` that holds the binary data for this message. This pulls TSIG/SIG(0)
  handling out of the client, simplifying it enormously as we can get rid of `dns.Conn`.
- `Msg` includes `Options` that control on how you want it packed/unpacked.
- `Msg` includes all the ENDS0 OPT RR bits, as this almost was a real message header; in this package it now is.
- `Msg` has a pseudo section that holds all EDNS0 Options as (faked) resource records.
- Everything is a resource record:

  - question section: holds `[]RR`
  - pseudo section: holds `[]RR`

  This will be extended (later/TODO) to allow reading from a text presentation format.

  There is also a `Stateful` section in the message that holds DNS Stateful Operation (DSO)
  records, these records will also be _RRs_.

- `New` will return an RR, `NewRR` will be gone.
- `Client` has a `dns.Transport` just like `http.Client`, so _all_ connection management is now external.
- More:
  - msg is a io.Writer.
  - msg.Data is re-used between request and reply in Exchange.
  - private RRs are easier.
  - private EDNS0 are almost implementable.
- SVCB record got its own package dns/svcb where all the key-values (called `svcb.Pair`) now reside.
- IsDuplicate is gone in favor of Compare and a full support for the `sort.Interface`, so you can just
  sort RRs in an RRset.
- Copy is gone... I think this was only use the message level and can be emulated by copying the buffer and
  calling `Unpack`.
- Copied and sanitized all the tests that accumulated over 16 years of development.

### Setting EDNS0

```
OLD                                           | NEW
                                              |
m := new(dns.Msg)                             | m := dns.NewMsg("miek.nl.", dns.TypeDNSKEY)
m.SetQuestion("miek.nl.", dns.TypeDNSKEY)     | m.UDPSize = 4096
                                              | m.Security = true
m.SetEdns0(4096, true)                        |
```

Setting the UDP buffer size:

```
OLD                                                      | NEW
                                                         |
bufsize := 0                                             | bufsize := m.UDPSize
for i := len(m.Extra) - 1; i >= 0; i-- {                 |
    if m.Extra[i].Header().Rrtype == dns.TypeOPT {       |
		bufsize = m.Extra[i].(*dns.OPT).UDPSize()        |
    }                                                    |
}                                                        |
```

Accessing ENDS0 options:

```
OLD                                                      | NEW
                                                         |
opt := 0                                                 | for i, options := range m.Pseudo {
for i := len(m.Extra) - 1; i >= 0; i-- {                 |     // ...
	if m.Extra[i].Header().Rrtype == dns.TypeOPT {       | }
	opt = m.Extra[i].(*dns.OPT)|                         |
    }                                                    |
}                                                        |
for i, options := range opt.Options {                    |
    // ...                                               |
}                                                        |
```

Adding an EDNS0 option is just as easy, assign to the pseudo section:

```
OLD                                                               |
                                                                  |
o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}} |
o.SetDo()                                                         | m.Security = true
o.SetUDPSize(dns.DefaultMsgSize)                                  | m.UDPSize = dns.DefaultMsgSize
e := &dns.EDNS0_NSID{Code: dns.EDNS0NSID}                         | m.Pseudo = append(m.Pseudo, &dns.NSID{})
o.Option = append(o.Option, e)                                    |
m.Extra = append(m.Extra, o)                                      |
```

### Text Output

Note the `do` flag now being shown as if it was set in the message header, OPT options are displayed as RRs
and can also be created with `dns.New`.

```
OLD                                                                  | NEW
                                                                     |
;; opcode: QUERY, status: NOERROR, id: 62167                         | ;; QUERY, rcode: NOERROR, id: 3, flags: rd do
;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0 | ;; EDNS, version: 0, udp: 1024
                                                                     | ;; QUESTION: 1, PSEUDO: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0, DATA SIZE: 25
;; OPT PSEUDOSECTION:                                                |
; EDNS: version 0; flags:; udp: 512                                  | ;; PSEUDO SECTION:
; NSID: 6770646e732d616d73  (g)(p)(d)(n)(s)(-)(a)(m)(s)              | .               CLASS0  NSID    6770 ; ("gpdns-ams")
                                                                     |
;; QUESTION SECTION:                                                 |
;miek.nl.       IN       MX                                          | ;; QUESTION SECTION:
                                                                     | miek.nl.                IN      A
```

### Copy

```
OLD                   | NEW
                      |
r := m.Copy()         | r := &dns.Msg{Data: m.Data}
                      | r.Unpack()
```

### Server

Because Msg now carries its binary data too (you can still discard it) there is no need to do TSIG in the
server it self, it can now be done in a handler. This, again, removes a little of internal code that slowed
things down.

The default implementation of `dns.ResponseWriter` is thread safe and this allows for TCP pipelining, which
is thusly implemented in `dns.Server`. Writing or reading data is now done with `io.Copy` no more `ReadMsg` or
`WriteMsg`.

# Users

A not-so-up-to-date-list-that-may-be-actually-current:

- sndns - my (Miek) private fork of CoreDNS.

Send pull request if you want to be listed here.

# Features

- UDP/TCP queries, TCP query-pipelining, IPv4 and IPv6.
- Fast(er).
- RFC 1035 zone file parsing ($INCLUDE, $ORIGIN, $TTL and $GENERATE - for _all_ record types) is supported.
- Server side programming (mimicking the net/http package), with `dns.Handle` and `dns.HandleFunc` allowing
  for middleware servers.
- Client side programming.
- DNSSEC: signing, validating and key generation for DSA, RSA, ECDSA and Ed25519.
- EDNS0, NSID, Cookies, etc, as pseudo RRs in the (fake) pseudo section.
- AXFR/IXFR.
- TSIG, SIG(0).
- Dynamic updates.
- DNS over TLS (DoT): encrypted connection between client and server over TCP.
- Examples included the cmd/ directory.

Have fun!

Miek Gieben - 2025- - <miek@miek.nl>

# Building

This library uses Go modules and uses semantic versioning. Building is done with the `go` tool, so
the following should work:

    go get codeberg.org/miekg/dns
    go build codeberg.org/miekg/dns

## Examples

A short "how to use the API" is at the beginning of doc.go (this also will show when you call `godoc codeberg.org/miekg/dns`).
The cmd/ directory contains a few example programs.

## Supported RFCs

_all of them_

- 103{4,5} - DNS standard
- 1348 - NSAP record (removed the record)
- 1982 - Serial Arithmetic
- 1876 - LOC record
- 1995 - IXFR
- 1996 - DNS notify
- 2136 - DNS Update (dynamic updates)
- 2181 - RRset definition
- 2537 - RSAMD5 DNS keys
- 2065 - DNSSEC (updated in later RFCs)
- 2671 - EDNS record
- 2782 - SRV record
- 2845 - TSIG record
- 2915 - NAPTR record
- 2929 - DNS IANA Considerations
- 3110 - RSASHA1 DNS keys
- 3123 - APL record
- 3225 - DO bit (DNSSEC OK)
- 340{1,2,3} - NAPTR record
- 3445 - Limiting the scope of (DNS)KEY
- 3596 - AAAA record
- 3597 - Unknown RRs
- 4025 - A Method for Storing IPsec Keying Material in DNS
- 403{3,4,5} - DNSSEC
- 4255 - SSHFP record
- 4343 - Case insensitivity
- 4408 - SPF record
- 4509 - SHA256 Hash in DS
- 4592 - Wildcards in the DNS
- 4635 - HMAC SHA TSIG
- 4701 - DHCID
- 4892 - id.server
- 5001 - NSID
- 5155 - NSEC3 record
- 5205 - HIP record
- 5702 - SHA2 in the DNS
- 5936 - AXFR
- 5966 - TCP implementation recommendations
- 6605 - ECDSA
- 6725 - IANA Registry Update
- 6742 - ILNP DNS
- 6840 - Clarifications and Implementation Notes for DNS Security
- 6844 - CAA record
- 6891 - EDNS0 update
- 6895 - DNS IANA considerations
- 6944 - DNSSEC DNSKEY Algorithm Status
- 6975 - Algorithm Understanding in DNSSEC
- 7043 - EUI48/EUI64 records
- 7314 - DNS (EDNS) EXPIRE Option
- 7477 - CSYNC RR
- 7828 - edns-tcp-keepalive EDNS0 Option
- 7553 - URI record
- 7719 - DNS Terminology
- 7858 - DNS over TLS: Initiation and Performance Considerations
- 7871 - EDNS0 Client Subnet
- 7873 - Domain Name System (DNS) Cookies
- 8080 - EdDSA for DNSSEC
- 8499 - DNS Terminology
- 8659 - DNS Certification Authority Authorization (CAA) Resource Record
- 8777 - DNS Reverse IP Automatic Multicast Tunneling (AMT) Discovery
- 8914 - Extended DNS Errors
- 8976 - Message Digest for DNS Zones (ZONEMD RR)
- 9461 - Service Binding Mapping for DNS Servers
- 9462 - Discovery of Designated Resolvers
- 9460 - SVCB and HTTPS Records
- 9499 - DNS Terminology
- 9567 - DNS Error Reporting
- 9606 - DNS Resolver Information

## Loosely Based Upon

- ldns - <https://nlnetlabs.nl/projects/ldns/about/>
- NSD - <https://nlnetlabs.nl/projects/nsd/about/>
- Net::DNS - <http://www.net-dns.org/>
- GRONG - <https://github.com/bortzmeyer/grong>
