# metrics

## Name

_metrics_ - enable [prometheus](https://prometheus.io/) metrics

## Description

With _metrics_ you export metrics from testserv and any handler that extra metrics.
The default address for the metrics is `localhost:9153`. The metrics path is fixed to `/metrics`.
See the global handler for details on how to change this. You must still enable metrics in the server block,
this allows you to specify where in the handler chain the metrics are gathered. Usually this is the first
handler. If the global section doesn't specify _metrics_ the metrics will not be able to be scraped.

In addition to the default Go metrics exported by the [prometheus Go
client](https://prometheus.io/docs/guides/go-application/), the following metrics are exported:

- `testserv_dns_dropped_total{}` - total count of dropped queries, because they are invalid, these will always
  be reported even with `metrics disable`, as this happens before the query hits this handler.
- `testserv_dns_requests_total{zone, proto, family, flags}` - total query count.
- `testserv_dns_responses_total{zone, proto, family, rcode}` - response per, among other things, the response code.
- `testserv_dns_request_duration_seconds{zone, proto, family}` - duration to process each query.
- `testserv_dns_request_size_bytes{zone, proto, family}` - size of the request in bytes.
- `testserv_dns_response_size_bytes{zone, proto, family}` - response size in bytes.

* `proto` which holds the transport of the response ("udp" or "tcp")
* The address family (`family`) of the transport (1 = IP (IP version 4), 2 = IP6 (IP version 6)).
* `flags` is a string that consists out of header flags mnemonics seperated by spaces:
  - `flags="co do"` means the CO (compact answers) and DO (dnssec ok) are set.
  - The recognized flags are: co - compact answers, do - dnssec ok and de - deleg ok.

If a server want to not partake in the metrics collection it sets `metrics disable` in the configuration. The default is
to allow metrics gathering.

## Syntax

Enable metrics in your server.

```txt
metrics
```

Or optionally.

```txt
metrics enable
```

Or to disable.

```txt
metrics disable
```

## Examples

Start a server on the default port and load the _whoami_ handler and disable metrics.

```corefile
example.org {
    metrics disable
    whoami
}
```
