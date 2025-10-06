# Name

_log_ - log queries

# Description

By just using _log_ you dump all queries on standard output. Note that for busy servers logging will incur a
performance hit. The _log_ handler only logs properties of the incoming query.

Enabling or disabling the _log_ handler only affects the query logging, any other logging from atomdns will
show up regardless.

The logging of a running server can be toggled by sending the processs a SIGUSR1 signal. This is a process
wide toggle, all logging of all server is enabled or disabled.

# Syntax

```txt
log
```

A typical example looks like this:

```txt
2025/10/06 07:25:52 INFO example.org. remote=::1 port=40689 id=23343 type=MX class=IN name=example.ORG. network=udp size=52 bufsize=1232 opcode=QUERY
```

Which says:

- Zone getting the request: `example.org.`.
- Remote address and port: `::1 40689`.
- Query ID `23343`.
- Question type, question class, incoming question name: `MX IN example.ORG.`.
- Network: `udp`.
- Size in bytes: `52`.
- Advertised UDP buffer: `1232`.
- Opcode: `QUERY`.

# Also See

signal(7).
