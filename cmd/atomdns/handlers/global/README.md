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
    health [ADDRESS [LAMEDUCK]]
    pprof [ADDRESS]
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
- With `health` you start a local web server that exports a /health endpoint on **ADDRESS** that returns 200 OK when
  everything is OK. When **LAMEDUCK** which should be a time.Duration in string form is given, the server' shutdown will be
  delayed for that duration. The default for \*_ADDRESS_ is `:8080`. Every 2 seconds atomdns will query itself
  to get its health so it can export the latency metrics.
- With `pprof` you can publish runtime profiling data at the endpoint on
  **ADDRESS** under `/debug/pprof`. The default is localhost:6053.

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

Or run an health endpoint on http://localhost:8091, with a lameduck delay of 200 ms.

```conffile
{
    health localhost:8091 200ms
}
```

## Metrics

If monitoring is enabled (via `metrics`) and `health` is enabled the following metrics are exported:

- `atomdns_health_request_duration_seconds{}` - `health` performs a self health check
  once per second on the `/health` endpoint. This metric is the duration to process that request.
  As this is a local operation it should be fast. A (large) increase in this
  duration indicates the atomdns process is having trouble keeping up with its query load.
- `atomdns_health_request_failures_total{}` - The number of times the self health check failed, this also
  points to imminent failure.
