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
    dns {
        quiet
        addr ADDRESS
        limits {
            tcp LIMIT
            run EXPR
        }
    }
    doh {
        addr ADDRESS
        limits {
            run EXPR
        }
    }
    tls ISSUER {
        cert CERT KEY [CA]
        contact EMAIL
        path PATH
    }
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

### `dns`

With `dns` you set DNS (port (usually) 53, TCP and UDP) server options, defined are.

- `quiet`: show banner during startup, and less messages.
- `addr` **ADDRESS**: listen on this address, default is `[::]:53`.
- `limits` set further limits:
  - `tcp` **LIMIT**, break off TCP connections after this many queries, default is 128, -1 disables.
  - `run` **EXPR**, run this many servers the default is `NumCPU*3`, this can be a bare number,
    like 5, or an expression like `NumCPU()*N`, where **N** is a whole number. `NumCPU()` may be spelled in
    lowercase. Also note that adding more servers helps with lock contention when writing the DNS messages
    back to the client. This is again multiplied by 2 for 50% UDP, and 50% TCP server. So `run 5`, will
    start 10 server instances.

### `doh`

With `doh` you set http server options, defined are.

- `addr` **ADDRESS**: listen on this address, default is `[::]:443`.
- `limits` set further limits:
  - `run` **EXPR**, run this many servers the default is `NumCPU*1`, this can be a bare number,
    like 5, or an expression like `NumCPU()*N`, where **N** is a whole number. `NumCPU()` may be spelled in
    lowercase.

Further server options like `dot` (DNS over TLS) and `doq` (DNS over QUIC) will be added in the future.

### `tls`

With `tls` you configure the TLS certificate setup. **ISSUER** can be `manual`, or `lets-encrypt`. The later
will set up the certicates automatically. If you use relative path in this configuration be sure that `root`
is set _above_ this config, so that its value is set.

Depending on **ISSUER**, you have the following further configuration:

If **ISSUER** is `manual`:

- `cert`, that lists in that order **CERT** the `cert.pem` (as an example name) file, **KEY** the private key,
  `key.pem` and optionally the `ca.pem` file.

If **ISSUER** is `lets-encrypt`:

- `contact`, where **EMAIL** is the contact email use when retrieving certificates.
- `path` has the **PATH** where the certificates are stored. The global's `root` is prepended if this a
  relative path name.

## Examples

This runs both a DNS and DOH server, the DOH server listens on port 8053.

```txt
{
    root /var/lib/atomdns
    metrics localhost:9153
    dns {
        limits {
            tcp -1
            run NumCPU()*3
        }
    }
    doh {
        addr [::]:8053
    }
}

example.org {
    log
    whoami
}
```

Or run an health endpoint on http://localhost:8091, with a lame-duck delay of 200 ms.

```txt
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
