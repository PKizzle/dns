## atomdns

_atomdns_ - DNS nameserver that runs handlers

## Synopsis

_atomdns_ **[-c CONFFILE]** **[-handler|-v|-version]**...

## Description

atomdns is a DNS server that chains handlers. Each handler handles a DNS feature, like serve zone files,
transfering those to secondaries or just exporting metrics. There are many handlers, each described in their
respective manual pages.

The _global_ handler describes the options that are also used in starting the server, see atomdns-global(7)
for more information. Normally you need a **CONFFILE** (atomdns-conffile(5)) like this, to listen on all interfaces on port 53:

```conffile
{
    server {
        addr [::]:53
    }
}

```

Available options:

**-c**, **-conf** **CONFFILE**
: specify configuration file to load, if not given atomdns will look for a `Conffile` in the current directory, if that
is also not found, it will use a built-in (test) Conffile:

```confffile
{
  server {
      addr [::]1053
  }
}

example.org {
  log
  whoami
}
```

**-handler**
: list all handlers and quit.

**-v**, **-version**
: show version and quit.

## Authors

atomdns authors.

## Copyright

Apache License 2.0

## See Also

See atomdns-conffile(5), and atomdns-global(7).
