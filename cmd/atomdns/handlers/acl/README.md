# acl

## Name

_acl_ - enforces access control policies

## Description

With _acl_, users are able to block or filter suspicious DNS queries by configuring IP filter rule sets, i.e.
allowing authorized queries or blocking unauthorized queries.

When evaluating the rule sets, _acl_ uses the source IP.

## Syntax

```
acl {
    ACTION [QTYPE]... [NET]...
}
```

- **ACTION** defines the way to deal with DNS queries matched by this rule. The default action is _allow_,
  DNS query not matched by any rules will be allowed to recurse. The difference between _block_ and _filter_

  - _allow_ forward the query to the next handler.
  - _block_ stop the query and return a _refused_ response.
  - _filter_ stop the query and returns _noerror_ response with the extended error (EDE) 'filtered'.
  - _drop_ stop the query and don't send any reply.

- **QTYPE** is the query type to match for the requests to be allowed or blocked. If **QTYPE** is omitted it
  matches _all_ types.
- **NET** is the source IP address to match for the requests to be allowed or blocked. Typical CIDR notation
  and single IP addresses are supported.

## Examples

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

Allow only DNS queries from 192.168.0.0/24 and 192.168.1.0/24:

```conffile
. {
    acl {
        allow 192.168.0.0/24 192.168.1.0/24
        block
    }
}
```

Block all DNS queries from 192.168.1.0/24 towards a.example.org:

```conffile
a.example.org {
    acl {
        block 192.168.1.0/24
    }
}
```

Drop all DNS queries from 192.0.2.0/24:

```conffile
. {
    acl {
        drop 192.0.2.0/24
    }
}
```

## Metrics

If monitoring is enabled (via the _prometheus_ plugin) then the following metrics are exported:

- `atomdns_acl_blocked_requests_total{zone, network, family}` - counter of DNS requests being blocked.

- `atomdns_acl_filtered_requests_total{zone, network, family}` - counter of DNS requests being filtered.

- `atomdns_acl_allowed_requests_total{zone, network, family}` - counter of DNS requests being allowed.

- `atomdns_acl_dropped_requests_total{zone, network, family}` - counter of DNS requests being dropped.

The `zone`,`network` and `family` labels are explained in the _metrics_ plugin documentation.

## Bugs

_acl_ should also check TSIG and other signed messages.
