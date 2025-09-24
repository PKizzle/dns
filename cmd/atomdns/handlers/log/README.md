# log

## Name

_log_ - log queries

## Description

By just using _log_ you dump all queries on standard output. Note that for busy servers logging will incur a
performance hit. The _log_ handler only logs properties of the incoming query.

Enabling or disabling the _log_ handler only affects the query logging, any other logging from atomdns will
show up regardless.

The logging of a running server can be toggled by sending the processs a SIGUSR1 signal. This is a process
wide toggle, all logging of all server is enabled or disabled.

## Syntax

```txt
log
```

A typical example looks like this:

```txt
2025/09/13 07:36:41 INFO ::1:58588 - 50123 "TXT IN bla.example.org. udp 56 1232" rd ad QUERY
```

Which says:

- Remote address and port: `::1:58588`.
- Query ID `50123`.
- Question type, question class, question name: `TXT IN bla.example.org.`.
- Network: `udp`.
- Size in bytes: `56`.
- Advertised UDP buffer: `1232`.
- Header flags: `rd ad`.
- Opcode: `QUERY`.

## Also See

signal(7).
