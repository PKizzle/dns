# log

## Name

_log_ - enables query logging to standard output.

## Description

By just using _log_ you dump all queries on standard output. Options exist to tweak the output. Note that for
busy servers logging will incur a performance hit. The _log_ handler only logs properties of the incoming query.

Enabling or disabling the _log_ handler only affects the query logging, any other logging from
testserv will show up regardless.

## Syntax

```txt
log
```

A typical example looks like this:

```txt
::1:50759 - 29008 "A IN example.org. udp 41 4096" NOERROR qr,rd,ra,ad,do 68 QUERY
```
