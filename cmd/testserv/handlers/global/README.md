# global

## Name

_global_ - hold global server properties

## Description

_global_ holds global server properties, like the prometheus metrics port and root directory.
It only implements the `Setupper` interface and it's not a handler and you can not use it as such.

## Syntax

```txt
root DIRECTORY
metrics [ADDRRES]
debug
```

- with _root_ **DIRECTORY** is the directory to use as the root directory for the server. Any relative path names will
  get this directory prefixed.
- with _debug_ the global log level is to debug.
- The _metrics_ property allows setting the listening **ADDRESS** for the promtheus metrics. This defaults to `localhost:9153`.
  Without _metrics_ no metrics can be scraped as the prometheus server isn't running, i.e. to allow for
  metrics gathering _metrics_ must be enabled in the global section.

## Examples

```conffile
{
    root /var/lib/testserv
    metrics localhost:9152
}
```
