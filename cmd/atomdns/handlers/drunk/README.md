# Name

_drunk_ - test client behavior

# Description

_drunk_ returns a static response to all queries, but the responses can be
delayed, dropped or truncated. The _drunk_ handler will respond to every A or
AAAA query. For any other type it will return a SERVFAIL response. The reply
for A will return 192.0.2.53 ([RFC 5737](https://tools.ietf.org/html/rfc5737)),
for AAAA it returns 2001:DB8::53 ([RFC 3849](https://tools.ietf.org/html/rfc3849)).

# Syntax

```txt
drunk {
    drop [/N]
    truncate [/M]
    delay [/L [DURATION]]
}
```

- `drop`: drop every /**N** query, the default is one in four (/4).
- `truncate`: truncate every /**M** query, the default is /4.
- `delay`: delay every /**L** query for **DURATION**, the default for is /22 and
  the default for **DURATION** is 100ms.

# Examples

Drop every 1 in 3 queries to `example.org`:

```conffile
example.org {
    drunk {
        drop /3
    }
}
```

Or even shorter if the defaults suit you. Note this only drops queries, it does not delay them.

```conffile
example.org {
    drunk
}
```

Delay 1 in 3 queries for 50ms

```conffile
example.org {
    drunk {
        delay /3 50ms
    }
}
```

Delay 1 in 3 and truncate 1 in 5.

```conffile
example.org {
    drunk {
        delay /3 5ms
        truncate /5
    }
}
```
