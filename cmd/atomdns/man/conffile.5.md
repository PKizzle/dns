## Name

_conffile_ - configuration file for atomdns

## Description

A _conffile_ specifies the internal servers sndns should run and what handlers each of these
should chain. The syntax is as follows:

```txt
ZONE [ZONE]... {
    [HANDLER]...
}
```

The **ZONE** defines for which DNS origins this server should be called, multiple zones are allowed and
should be _white space_ separated.

When a query comes in, it is matched again all zones for all servers, the server with the longest match on the
query name will receive the query.

**HANDLER** defines the handlers(s) we want to load into this server. This is optional as well, but as
server with no handlers will just return SERVFAIL for all queries. Each handlers can have a number of
properties than can have arguments, see the documentation for each handler.

The order of the **HANDLER**s is the order in which they are executed! (If you know CoreDNS, this is
different, as which CoreDNS the order is fixed compile time).

Comments are allowed and begin with an unquoted hash `#` and continue to the end of the line.
Comments may be started anywhere on a line.

Environment variables are supported and either the Unix or Windows form may be used: `{$ENV_VAR_1}`
or `{%ENV_VAR_2%}`.

You can use the `import` "handler" (See sndns-import(7)) to include parts of other files.

## Import

You can use the `import` "handler" to include parts of other files, see sndns-import(7).

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

The **ZONE** is root zone `.`, the **handler** is _chaos_. The _chaos_ plugin takes an (optional) argument:
`sndns-001`. This text is returned on a CH class query: `dig CH TXT version.bind @localhost`.

```conffile
. {
   chaos sndns-001
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

## Authors

atomdns authors.

## Copyright

Apache License 2.0

## See Also

The manual page for atomdns: atomdns(1) and all the manual pages for the handlers.
