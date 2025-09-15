# dbfile

## Name

_dbfile_ - serve zone data from an RFC 1035-style zone file

## Description

The _dbfile_ plugin is used for DNS servers that serve from a preloaded file that exists on disk
containing RFC 1035 styled data. If the zone file contains signatures (i.e., is signed using DNSSEC), correct
DNSSEC answers are returned. Only NSEC is supported. See the _sign_ plugin if you want to sign and resign your
zone automatically.

The server will reply with minimal responses by default. The _dbfile_ plugin will watch the zone file and when
it receives a (kernel) notify will reload the zone after 5 seconds. Regardless of any change it will send out
notifies if configured to do so, the actual SOA serial isn't relevant.

## Syntax

```
dbfile FILE
```

- **FILE** the database file to read and parse. If the path is relative, the path from the global root config
  will be prepended to it.

If the zone specification contains multiple zones they all will use the _same_ **FILE**.

For extra control you can open the block and define multipe properties.

```
dbfile FILE {
    transfer {
        from IP [IP]... {
            key NAME ALGORITHM SECRET
        }
        to IP [IP]... {
            notify [IP]... {
                source IP
            }
            key NAME ALGORITHM SECRET
        }
    }
}
```

- `transfer` details how zone transfers are handled, `from` deals with incoming AXFR from **IP**, and `to`
  deals with outgoing ones.

  - `from` allows for multiple upstream **IP**s to be specified, they will be tried in that order.
  - The `key` specification is for TSIG signed transfers. The **SECRET** must be base64 encoded.
  - `to` allows for multipe downstream **IP**s to be specified, those are all allowed to initiate a transfer.
  - If there is no `notify` section the **IP**s as specified in `to` are used for sending notifies. If you
    want to override this open a `notify` block and add an (optional) new set of **IP**s. With `source` you can
    set the source address when sending the notifies. The TSIG key specification is identical to that of `from`.
    For **IP** you can use IPv6 or IPv4 addresses. The wildcard address for them are `::/128` or `0.0.0.0/0`.
    `*` is an aliases for _both_ of them.

## Examples

Load the `example.org` zone from `db.example.org` and allow transfers to the internet, but send
notifies to 10.240.1.1

```conffile
example.org {
    file db.example.org
    transfer {
        to *
        notify 10.240.1.1
    }
}
```

Where `db.example.org` would contain RRs in the (text) presentation format from RFC 1035:

```
$ORIGIN example.org.
@	3600 IN	SOA sns.dns.icann.org. noc.dns.icann.org. 2017042745 7200 3600 1209600 3600
	3600 IN NS a.iana-servers.net.
	3600 IN NS b.iana-servers.net.

www     IN A     127.0.0.1
        IN AAAA  ::1
```

Or use a single zone file for multiple zones:

```conffile
example.org example.net {
    file example.org.signed {
        transfer {
            to 10.240.1.1
        }
    }
}
```

## See Also

See the _sign_ plugin for signing your zones and see [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.txt)
for more info on how to structure zone files.
