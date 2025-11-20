# Name

_acl_ - enforces access control policies

# Description

With _acl_, users are able to block or filter suspicious DNS queries by configuring IP filter rule sets, i.e.
allowing authorized queries or blocking unauthorized queries.

When evaluating the rule sets, _acl_ uses the source IP.

# Syntax

```
acl {
    ACTION [QTYPE|CTX]... [NET|VALUE]...
}
```

- **ACTION** defines the way to deal with DNS queries matched by this rule. The default action is _allow_,
  DNS query not matched by any rules will be allowed to continue. The following actions are defined:
  - _allow_ forward the query to the next handler.
  - _block_ stop the query and return a _refused_ response with the extended error (EDE) 'blocked'.
  - _filter_ stop the query and returns _noerror_ response with the extended error (EDE) 'filtered'.
  - _drop_ stop the query and don't send any reply.

- **QTYPE|CTX** is the query type to match for the requests to be allowed or blocked. If **QTYPE** is omitted it
  matches _all_ types. If a **CTX** is used it must be in the format `xxx/yyy`, i.e. two words seperated by a
  slash. The _geoip_ handler for instance writes data under the key `geoip/city`, that can be used here. If
  the key does not return any data it will considered a negative match.

- **NET|VALUE** is the source IP address or value from the context found under the key **CTX** to match for the
  requests to be allowed or blocked. Typical CIDR notation and single IP addresses are supported. A **VALUE**
  can be used if the context key is references previously Again with the _geoip_ handler and using
  `Cambridge` here you can have access control on a city level.

# Examples

To demonstrate the usage of _acl_, here we provide some typical examples.

Block all DNS queries with record type A from 192.168.0.0/16：

```conffile
. {
    acl {
        block A 192.168.0.0/16
    }
}
```

Filter all DNS queries with record type A from 192.168.0.0/16：

```conffile
. {
    acl {
        filter A 192.168.0.0/16
    }
}
```

Block all DNS queries from 192.168.0.0/16 except for 192.168.1.0/24:

```conffile
. {
    acl {
        allow 192.168.1.0/24
        block 192.168.0.0/16
    }
}
```

Drop all queries from Cambridge, this requires the _geoip_ handler to have populated the context for this
query. Allow all countries that are in the EU.

```conffile
. {
    acl {
        block geoip/city Cambridge
        allow geoip/country/eu true
    }
}
```

# Metrics

If monitoring is enabled (via the _metrics_ handler) then the following metrics are exported:

- `atomdns_acl_blocked_requests_total{zone, network, family}` - counter of DNS requests being blocked.
- `atomdns_acl_filtered_requests_total{zone, network, family}` - counter of DNS requests being filtered.
- `atomdns_acl_allowed_requests_total{zone, network, family}` - counter of DNS requests being allowed.
- `atomdns_acl_dropped_requests_total{zone, network, family}` - counter of DNS requests being dropped.

The `zone`,`network` and `family` labels are explained in the _metrics_ handler documentation.

# Bugs

_acl_ should also check TSIG and other signed messages.
