# metrics

## Name

_metrics_ - enable [prometheus](https://prometheus.io/) metrics

## Description

With _metrics_ metrics are exported from atomdns and any handler that adds extra ones.
The default address for the metrics server is `localhost:9153`. The metrics path is fixed to `/metrics`.
See the global handler for details on how to change the address.

You must also enable metrics in the server block, this allows you to specify where in the handler chain the
metrics are gathered. Usually this is the first handler. If the global section doesn't specify _metrics_ the
metrics will not be able to be scraped, but they are still gathered.

Enabling metrics means taking a (severe) performance hit (50 Kqps, seen in [limited] testing), to alleviate
this, by default, only 1 in 10 queries will be monitored. See the _global_ handler's documentation on how to change this.

In addition to the default Go metrics exported by the [prometheus Go
client](https://prometheus.io/docs/guides/go-application/), the following metrics are exported:

- `atomdns_dns_dropped_total{}` - total count of dropped queries, because they are invalid, these will always
  be reported even with `metrics disable`, as this happens before the query hits this handler.
- `atomdns_dns_requests_total{zone, network, family, flags}` - total query count.
- `atomdns_dns_responses_total{zone, network, family, rcode}` - response per, among other things, the response code.
- `atomdns_dns_request_duration_seconds{zone, network, family}` - duration to process each query.
- `atomdns_dns_request_size_bytes{zone, network, family}` - size of the request in bytes.
- `atomdns_dns_response_size_bytes{zone, network, family}` - response size in bytes.

* `network` which holds the transport of the response ("udp" or "tcp")
* The address family (`family`) of the transport (1 = IP (IP version 4), 2 = IP6 (IP version 6)).
* `flags` is a string that consists out of header flags mnemonics seperated by spaces:
  - `flags="co do"` means the CO (compact answers) and DO (dnssec ok) are set.
  - The recognized flags are: co - compact answers, do - dnssec ok, de - deleg ok, ad - authenticated data,
    and cd - checking disabled.

If a server want to not partake in the metrics collection it sets `metrics disable` in the configuration. The default is
to allow metrics gathering.

## Syntax

```txt
metrics [|enable|disable]
```

Where:

- _empty_ or `enable` will enable metrics gathering, only `disable` will disable it.

## Examples

Start a server on the default port and load the _whoami_ handler and disable metrics.

```conffile
{
    metrics
    debug
}

example.org {
    metrics disable
    whoami
}
```
