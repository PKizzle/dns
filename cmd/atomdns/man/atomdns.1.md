## atomdns

_atomdns_ - DNS nameserver that runs handlers

## Synopsis

_atomdns_ **[-c CONFFILE]** **[-C|-H|-V]**...

## Description

atomdns is a DNS server that chains handlers. Each handler handles a DNS feature, like serve zone files,
transfering those to secondaries or just exporting metrics. There are many handlers, each described in their
respective manual page.

The server atomdns can be reloaded by sending it the HUP signal, this reloads all handlers, but does _not_
restart any of the servers, so changes to server addresses and limits (see atomdns-global(7)) will not be
applied through reloads. For those kind of changes the server needs to be restarted.

The _global_ handler describes the options that are also used in starting the server, see atomdns-global(7)
for more information. Normally you need a **CONFFILE** (atomdns-conffile(5)) like this, to listen on all
interfaces on port 53:

```conffile
{
    dns {
        addr [::]:53
    }
}

```

Available options:

**-c**, **-config** **CONFFILE**
: specify configuration file to load, if not given atomdns will look for a `Conffile` in the current directory, if that
is also not found, it will use a built-in (test) Conffile:

```confffile
{
  dns {
      addr [::]1053
  }
}

example.org {
  log
  whoami
}
```

**-C**
: check the configuration, report any erors and exit with status 1 or if everything is OK exit with status
code 0.

**-H**
: list all handlers and quit.

**-V**
: Show version and quit.

## Authors

atomdns authors.

## Copyright

Apache License 2.0

## See Also

See atomdns-conffile(5), and atomdns-global(7).
