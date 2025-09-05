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

With no arguments, a query log entry is written to _stdout_ in the common log format for all requests.
Or if you want/need slightly more control:

```txt
log [FORMAT]
```

- **FORMAT** is the log format to use (see below for the default), this is copied from the Go template syntax.

## Log Format

You can specify a custom log format with any placeholder values. Log supports both request and
response placeholders.

The following place holders are supported:

- `{{type}}`: question type
- `{{name}}`: question name
- `{{class}}`: question class
- `{{network}}`: network used (tcp or udp)
- `{{remote}}`: client's IP address, for IPv6 addresses these are enclosed in brackets: `[::1]`
- `{{local}}`: server's IP address, for IPv6 addresses these are enclosed in brackets: `[::1]`
- `{{size}}`: request size in bytes
- `{{port}}`: client's port
- `{{flags}}`: response flags, each set flag will be displayed, e.g. "aa, tc". This includes the
  DNSSEC OK (do), compact answers (co), etc. too.
  bit as well
- `{{bufsize}}`: the udp buffer size advertised in the query
- `{{id}}`: query ID
- `{{opcode}}`: query opcode

The default log format is:

```txt
`{{remote}}:{{port}} - {{id}} "{{type}} {{class}} {{name}} {{network}} {{size}} {{bufsize}}" {{flags}} {{opcode}}`
```

Each of these logs will be outputted with `log.Infof`, so a typical example looks like this:

```txt
[INFO] [::1]:50759 - 29008 "A IN example.org. udp 41 4096" NOERROR qr,rd,ra,ad,do 68 QUERY
```

## Examples

Log all requests to stdout

```corefile
example.org. {
    log
    whoami
}
```

Custom log format, for all zones (`.`)

```corefile
. {
    log "{proto} Request: {name} {type} {>id}"
}
```
