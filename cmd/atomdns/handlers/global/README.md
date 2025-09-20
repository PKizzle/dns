# global

## Name

_global_ - hold global server properties

## Description

_global_ holds global server properties, like the prometheus metrics port and root directory.
It's not a handler and you can not use it as such: you can't use _global_ in the configuration, other than in the
global section, see the configuration example below.

## Syntax

```txt
{
    root DIRECTORY
    metrics [/N] [ADDRRES]
    debug
}
```

- with `root` **DIRECTORY** is the directory to use as the root directory for the server. Any relative path names will
  get this directory prefixed. If **DIRECTORY** itself is also relative the current working directory (cwd) of the atomdns
  process will be prefixed.
- with `debug` the global log level is to debug.
- The `metrics` property allows setting the listening **ADDRESS** for the promtheus metrics. This defaults to `localhost:9153`.
  Without `metrics` no metrics can be scraped as the prometheus server isn't running, i.e. to allow for
  metrics gathering `metrics` must be enabled in the global section.
  The optional **/N** tells the metric handler to monitor 1 in **N** queries. The default is 10. This needs to
  be a positive integer > 0. This is done to not impair performance too much.
  With the `metrics` handler you can enable/disable metrics on a per server basis.

## Examples

```conffile
{
    root /var/lib/atomdns
    metrics localhost:9153
}

example.org {
    log
    whoami
}
```
