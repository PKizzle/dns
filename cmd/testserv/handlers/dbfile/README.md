# dbfile

## Name

_dbfile_ - serve zone data from an RFC 1035-style zone file

## Description

The _file_ plugin is used for an "old-style" DNS server. It serves from a preloaded file that exists
on disk contained RFC 1035 styled data. If the zone file contains signatures (i.e., is signed using
DNSSEC), correct DNSSEC answers are returned, but only NSEC is supported. If you use this setup _you_
are responsible for re-signing the zonefile. See the _sign_ plugin if you want to sign and resign your zone
though.

## Syntax

```
dbfile FILE
```

- **FILE** the database file to read and parse. If the path is relative, the path from the global root config
  will be prepended to it.

For extra control you can open the block are define multipe properties.

```
dbfile FILE {
    reload DURATION
}
```

- `reload` will reload the zone every **DURATION** to check for SOA version changes. Default is one minute
  (`1m`). A value of `0` means to not scan for changes. For example, `30s` checks the zonefile every 30 seconds
  and reloads the zone when serial changes.
- `transfer` ...

## Examples

Load the `example.org` zone from `db.example.org` and allow transfers to the internet, but send
notifies to 10.240.1.1

```conffile
example.org {
    file db.example.org
    transfer {
        to * 10.240.1.1
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
        transfer example.org example.net {
            to * 10.240.1.1
        }
    }
}
```

## See Also

See the _sign_ plugin for signing your zones and see [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.txt)
for more info on how to structure zone files.
