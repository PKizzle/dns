# Name

_subnet_ - adds client subnet address

# Description

This handler adds the EDNS0 client subnet's (RFC 7871) subnet to the current context. If none is found, nothing
is added. Other handlers, like _geoip_ or _acl_ can use this data instead of the source IP address.

# Syntax

```txt
subnet
```

# Examples

Enable cookies:

```corefile
example.org {
    subnet
    whoami
}
```

# Context

The _ecs_ handler adds a single key to the context:

| Key              | Type     | Example      | Description       |
| :--------------- | :------- | :----------- | :---------------- |
| `subnet/address` | `string` | 198.51.100.1 | The subnet value. |

# See Also

See RFC 7871.
