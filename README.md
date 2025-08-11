# WORK IN PROGRESS

Things compile, the few tests work, but expect breakage, or large things to change.

[![](https://godoc.org/codeberg.org/miekg/dns?status.svg)](https://godoc.org/codeberg.org/miekg/dns)

# Alternative (more granular) approach to a DNS library (version 2)

> Less is more.

Complete and usable DNS library. All Resource Records are supported, including the DNSSEC types. It follows a
lean and mean philosophy. Server side and client side programming is supported, i.e. you can build servers and
resolvers with it.

We try to keep the "main" branch as sane as possible and at the bleeding edge of standards, avoiding breaking
changes wherever reasonable.

# Goals

- KISS.
- Everything is an RR.
- Fast.
- Small API.

## Difference with github.com/miekg/dns

- `Msg` contains a buffer named Data that holds the binary data for this package. This pulls TSIG/SIG(0)
  handling out of the client, simplifying it enormously as we can get rid of `dns.Conn`.
- `Msg` includes all the ENDS0 OPT RR bits, as this almost was a real message header; in this package it now
  is.
- `Msg` includes `Options` that control on how you want it packed/unpacked.
- `Msg` has a pseudo section that holds all EDNS0 Options as (faked) resource records.
- Everything is a resource record:

  - question section: hold an RR
  - pseudo section: holds RRs

  This will be extended (later/TODO) to allow reading from a text presentation format.

- `New` will return an RR, `NewRR` will be gone.
- `Client` has a `dns.Transport` just like `http.Client`, so _all_ connection management is now external.

### Setting EDNS0

Both `SetQuestion` and `SetEdns0` are extra helper methods, build on top of the core library, here
I'm still contemplating if that is even necessary.

```
OLD                                           | NEW
                                              |
m := new(dns.Msg)                             | m := &dns.Msg{MsgHeader: MsgHeader{ID: dns.ID(), RecursionDesired: true}}
m.SetQuestion("miek.nl.", dns.TypeDNSKEY)     | key := &DNSKEY{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET}}
                                              | m.Question = []RR{key}
m.SetEdns0(4096, true)                        | m.UDPSize = 4096
                                              | m.Security = true
```

For `IsEdns0` (again helper function) the following is done to just get the UDPSize or the DO-bit, you then need to retrieve the bits
from the `OPT` RR.

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

Accessing ENDS0 options, again requires getting the `OPT` and getting the options from there.

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

# Users

A not-so-up-to-date-list-that-may-be-actually-current:

- sndns - my (Miek) private fork of CoreDNS.

Send pull request if you want to be listed here.

# Features

- UDP/TCP queries, IPv4 and IPv6
- RFC 1035 zone file parsing ($INCLUDE, $ORIGIN, $TTL and $GENERATE (for all record types) are supported
- Fast
- Server side programming (mimicking the net/http package)
- Client side programming
- DNSSEC: signing, validating and key generation for DSA, RSA, ECDSA and Ed25519
- EDNS0, NSID, Cookies
- AXFR/IXFR
- TSIG, SIG(0)
- DNS over TLS (DoT): encrypted connection between client and server over TCP

Have fun!

Miek Gieben - 2025- - <miek@miek.nl>

# Building

This library uses Go modules and uses semantic versioning. Building is done with the `go` tool, so
the following should work:

    go get codeberg.org/miekg/dns
    go build codeberg.org/miekg/dns

## Examples

A short "how to use the API" is at the beginning of doc.go (this also will show when you call `godoc
github.com/miekg/dns`).

## Supported RFCs

_all of them_

- 103{4,5} - DNS standard
- 1348 - NSAP record (removed the record)
- 1982 - Serial Arithmetic
- 1876 - LOC record
- 1995 - IXFR
- 1996 - DNS notify
- 2136 - DNS Update (dynamic updates)
- 2181 - RRset definition - there is no RRset type though, just []RR
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
- 3597 - Unknown RRs
- 4025 - A Method for Storing IPsec Keying Material in DNS
- 403{3,4,5} - DNSSEC + validation functions
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
- 7858 - DNS over TLS: Initiation and Performance Considerations
- 7871 - EDNS0 Client Subnet
- 7873 - Domain Name System (DNS) Cookies
- 8080 - EdDSA for DNSSEC
- 8499 - DNS Terminology
- 8659 - DNS Certification Authority Authorization (CAA) Resource Record
- 8777 - DNS Reverse IP Automatic Multicast Tunneling (AMT) Discovery
- 8914 - Extended DNS Errors
- 8976 - Message Digest for DNS Zones (ZONEMD RR)

## Loosely Based Upon

- ldns - <https://nlnetlabs.nl/projects/ldns/about/>
- NSD - <https://nlnetlabs.nl/projects/nsd/about/>
- Net::DNS - <http://www.net-dns.org/>
- GRONG - <https://github.com/bortzmeyer/grong>
