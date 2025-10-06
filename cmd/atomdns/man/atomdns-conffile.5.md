## Name

_conffile_ - configuration file for atomdns

## Description

A _conffile_ specifies the internal servers atomdns should run and what handlers each of these
should chain. The syntax is as follows:

```txt
ORIGIN [ORIGIN]... {
    [HANDLER]...
}
```

Such a section is called a server block. Each block defines the handlers this particular server should run
when it gets a query.

The **ORIGIN** defines for which DNS zones this server should be called, multiple zones are allowed and must
be _white space_ separated.

When a query comes in, it is matched again all zones for all servers, the server with the longest match on the
query name will receive the query.

**HANDLER** defines the handlers(s) we want to load into this server. This is optional as well, but as
server with no handlers will just return SERVFAIL for all queries. Each handlers can have a number of
properties than can have arguments, see the documentation for each handler (atomdns-**HANDLER**(7)).

The order of the **HANDLER**s is the order in which they are executed! (If you know CoreDNS, this is
different, as which CoreDNS the order is fixed compile time). I.e. putting the _log_ handler (atomdns-log(7))
as last, means no queries are logged.

Comments are allowed and begin with an unquoted hash `#` and continue to the end of the line. Comments may be
started anywhere on a line.

Environment variables are supported and either the Unix or Windows form may be used: `{$ENV_VAR_1}`
or `{%ENV_VAR_2%}`.

As an way to test things Conffile also supports a shorter way of writing things done, but this only works for
a single server:

```conffile
ORIGIN [ORIGIN]...
[HANDLER]...
```

I.e.

```txt
example.org
log
whoami
```

Is a valid config and is supported by `atomdns`.

## Global

A Conffile can have a global section, this is a section without an origin and holds various server wide
options, like how many instances, if you want DOH and DOT servers, etc. etc. For each server type (DNS, DOT
and DOH) you have a section `dns`, `dot` and `doh` where you can configure the server, most notably the
address and port you want to listen on.

```txt
{
    dns {
        addr [::]:1053
    }
    root /var/lib/atomdns
    metrics localhost:9153
}
```

See atomdns-global(7) for more information.

## Import

You can use the _import_ "handler" to include parts of other files, or snippets that are defined in the config
file see atomdns-import(7). To prevent infinite recursion a maximum of a 1000 imports are allowed.

## Snippets

If you want to reuse a snippet you can define one with and then use it with _import_.

```conffile
(mysnippet) {
    log
    whoami
}

example.org {
    import mysnippet
}
```

## Examples

The **ZONE** is root zone `.`, the **handler** is _chaos_. The _chaos_ handler takes an (optional) argument:
`atomdns-001`. This text is returned on a CH class query: `dig CH TXT version.bind @localhost`.

```conffile
. {
   chaos atomdns-001
}
```

When defining a new zone, you either create a new server, or add it to an existing one. Here we
define one server that handles two zones; that potentially chain different handlers:

```conffile
example.org {
    whoami
}
org {
    whoami
}
```

Is identical to:

```conffile
example.org org {
    whoami
}
```

Reverse zones can be specified as domain names:

```conffile
0.0.10.in-addr.arpa {
    whoami
}
```

or by just using the CIDR notation:

```conffile
10.0.0.0/24 {
    whoami
}
```

This also works on a non octet boundary:

```conffile
10.0.0.0/27 {
    whoami
}
```

Doing Let's Encrypt certificates for your DOH servers:

```conffile
{
    root /var/lib/atomdns

    dns {
        addr [::]:1053
        limits {
            tcp -1
            run numcpu()*3
        }
    }
    doh {
        addr [::]:10053
        limits {
            run numcpu()*1
        }
    }
    tls lets-encrypt {
        source eth0
        contact miek@miek.nl
        path lets-encrypt
    }
}

example.net {
    log
    dbfile example.net
}
```

## Authors

atomdns authors.

## Copyright

Apache License 2.0

## See Also

The manual page for atomdns: atomdns(1) and the manual pages for the handlers.
