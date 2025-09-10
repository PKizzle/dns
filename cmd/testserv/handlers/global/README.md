# global

## Name

_global_ - hold global server properties

## Description

_global_ holds global server properties, like the prometheus metrics port and root directory.
It only implements the `Setupper` interface and it's not a handler and you can not use it as such.

## Syntax

```txt
root DIRECTORY
metrics [/N] [ADDRRES]
debug
```

- with _root_ **DIRECTORY** is the directory to use as the root directory for the server. Any relative path names will
  get this directory prefixed. If **DIRECTORY** itself is also relative the current working directory (cwd) of the testserv
  process will be prefixed.
- with _debug_ the global log level is to debug.
- The _metrics_ property allows setting the listening **ADDRESS** for the promtheus metrics. This defaults to `localhost:9153`.
  Without _metrics_ no metrics can be scraped as the prometheus server isn't running, i.e. to allow for
  metrics gathering _metrics_ must be enabled in the global section.
  The optional **/N** tells the metric handler to monitor 1 in **N** queries. The default is 10. This needs to
  be a positive integer > 0.

## Examples

```conffile
{
    root /var/lib/testserv
    metrics localhost:9152
}
```
